//! `audit_sink` entity kind — tamper-evident compliance audit stream.
//!
//! Per spec §9.12, canonical use cases:
//!
//! - SOC2 / HIPAA / PCI-DSS audit logs.
//! - Immutable security event log.
//! - Record of admin actions (plugin enable/disable/drain, config
//!   reload, trust changes).
//! - Record of denied accesses (tool-gate denies, policy engine
//!   denies, identity-chain rejections).
//!
//! # Fan-out + synchronous-ack contract
//!
//! Every registered audit sink receives every event — the composition
//! is explicitly fan-out, not pipeline, because auditors care about
//! tamper evidence: a compromised sink cannot drop events that other
//! sinks also receive. Each sink's `emit` MUST durably persist before
//! returning Ok; the gateway awaits every sink's Ok before continuing
//! the request that produced the event (unless the operator opts
//! into `governance.audit.on_failure: fail_open`, which flips to
//! best-effort).
//!
//! # Hash chaining
//!
//! Each event's `prev_event_hash` is the SHA-256 of the previous
//! event's canonical JSON form (with its own `prev_event_hash`
//! field included). A gap in the chain is detectable by consumers —
//! auditors run chain-verification as their first integrity check.
//! The protocol specifies the field; sinks that want tamper
//! evidence compute + verify the chain themselves.

use serde::{Deserialize, Serialize};

use crate::manifest::PluginManifest;
use crate::types::PluginIdentity;

/// One audit event passed to every registered sink. Timestamps are
/// RFC 3339 UTC strings to avoid pulling a `chrono` dep into the
/// protocol crate; plugin authors typically use
/// `chrono::Utc::now().to_rfc3339()` to produce them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    /// Unique event identifier (UUID v7 recommended for sortability).
    /// Caller supplies; the protocol does not mint UUIDs so the
    /// protocol crate can stay dependency-free.
    pub event_id: String,
    /// RFC 3339 UTC timestamp when the event occurred. SHOULD be the
    /// wall-clock time the underlying operation started.
    pub occurred_at: String,
    /// Caller identity at the time of the event. For operator /
    /// startup events use a synthesised identity with
    /// `kind = "system"`.
    pub actor: PluginIdentity,
    /// Dotted action identifier, e.g. `"tool.call.allowed"`,
    /// `"plugin.disabled"`, `"mcpg.lifecycle.gateway_started"`.
    pub action: String,
    /// Optional resource URI the action operated on, e.g.
    /// `"tool://payments.charge"` or `"plugin://dev.mcpg.audit"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Outcome class.
    pub outcome: AuditOutcome,
    /// MCP request id the event is tied to (tool-call audits, policy
    /// decisions); `None` for gateway-lifecycle events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Logical node identifier when the gateway runs as part of a
    /// multi-node deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Action-specific structured detail. Sinks MUST treat this as
    /// opaque JSON — the shape is determined by `action`.
    #[serde(default)]
    pub details: serde_json::Value,
    /// SHA-256 of the previous event's canonical JSON form, hex
    /// encoded. `None` for the genesis event. The protocol
    /// specifies the field; sinks that want tamper evidence compute
    /// + verify the chain themselves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_event_hash: Option<String>,
}

/// Outcome class. Sinks often index on this for fast filter queries
/// in their downstream store.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Failure,
    /// Operation partially succeeded — e.g. a multi-step pipeline
    /// where some steps completed. Sinks MAY surface this as a
    /// distinct severity class.
    Partial,
    /// Policy / gate / identity-chain refused the operation. Distinct
    /// from `Failure` so compliance dashboards can separate
    /// "denied" (expected) from "errored" (not expected).
    Denied,
}

impl std::fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
            Self::Partial => write!(f, "partial"),
            Self::Denied => write!(f, "denied"),
        }
    }
}

/// Receipt returned by `emit`. Carries the sink's own id + the hash
/// it computed over the event — consumers re-derive the hash chain
/// from the receipts plus the original events to prove no gaps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditReceipt {
    /// Plugin id of the sink that acknowledged (the same value as
    /// `PluginManifest.id`).
    pub sink_id: String,
    /// RFC 3339 UTC time the sink finished durable write.
    pub persisted_at: String,
    /// Hex-encoded SHA-256 of the event's canonical form, as the
    /// sink computed it. Consumers check this matches their own
    /// recomputation on replay.
    pub durable_hash: String,
}

/// Failure modes for `emit` / `flush`. The gateway translates each
/// variant into a different observability signal + policy decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditError {
    /// Durable write failed. Carries a short human-readable reason.
    WriteFailed { reason: String },
    /// Sink is rate-limited / queue-bounded and back-pressured.
    /// Gateway records the event to the local fallback log and
    /// retries on the next event if the sink supports reconnection.
    Throttled,
    /// Sink is in a terminal shut-down state. Gateway treats this
    /// the same as `WriteFailed` for policy purposes.
    Closed,
    /// Sink did not return within the operator-configured timeout.
    Timeout,
}

impl AuditError {
    /// Short identifier suitable as a metrics label. Avoids leaking
    /// the free-form `reason` string into Prometheus cardinality.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::WriteFailed { .. } => "write_failed",
            Self::Throttled => "throttled",
            Self::Closed => "closed",
            Self::Timeout => "timeout",
        }
    }
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WriteFailed { reason } => {
                write!(f, "audit write failed: {reason}")
            }
            Self::Throttled => write!(f, "audit sink throttled"),
            Self::Closed => write!(f, "audit sink closed"),
            Self::Timeout => write!(f, "audit sink timeout"),
        }
    }
}

impl std::error::Error for AuditError {}

/// The `audit_sink` entity trait. Every plugin providing an audit
/// surface implements this; the gateway fans every event out to
/// every registered sink.
#[crate::async_trait]
pub trait AuditSink: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// Emit an audit event. The sink MUST durably persist (fsync /
    /// ack-from-backend) before returning Ok. A `Result::Ok`
    /// receipt is the gateway's contract that the event is safe.
    ///
    /// Per spec §9.12, the gateway awaits every registered sink's
    /// Ok before completing the request that produced the event
    /// (unless the operator opts into fail-open).
    async fn emit(&self, event: &AuditEvent) -> Result<AuditReceipt, AuditError>;

    /// Force a durable flush of any buffered state. Called at
    /// gateway shutdown and by admin on demand. Default impl is a
    /// no-op — sinks that buffer MUST override.
    ///
    /// Implementations SHOULD respect `timeout_ms` as a deadline
    /// hint; exceeding it returns `AuditError::Timeout`.
    async fn flush(&self, timeout_ms: u64) -> Result<(), AuditError> {
        let _ = timeout_ms;
        Ok(())
    }

    /// Called on gateway shutdown. Default is a no-op; sinks with
    /// connections or buffered state SHOULD override to drain
    /// before the host drops the handle.
    async fn shutdown(&self) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity() -> PluginIdentity {
        PluginIdentity {
            kind: "anonymous".into(),
            trust_level: "unauthenticated".into(),
            subject_id: None,
            auth_provider: None,
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn audit_event_roundtrip_json() {
        let event = AuditEvent {
            event_id: "01930000-0000-7000-8000-000000000000".into(),
            occurred_at: "2026-04-24T12:00:00Z".into(),
            actor: sample_identity(),
            action: "tool.call.denied".into(),
            resource: Some("tool://payments.charge".into()),
            outcome: AuditOutcome::Denied,
            request_id: Some("req-1".into()),
            node_id: None,
            details: serde_json::json!({"reason": "rate_limit"}),
            prev_event_hash: Some("deadbeef".repeat(8)),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let parsed: AuditEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, parsed);
    }

    #[test]
    fn audit_outcome_snake_case_wire_format() {
        assert_eq!(
            serde_json::to_string(&AuditOutcome::Success).unwrap(),
            "\"success\""
        );
        assert_eq!(
            serde_json::to_string(&AuditOutcome::Denied).unwrap(),
            "\"denied\""
        );
        assert_eq!(
            serde_json::to_string(&AuditOutcome::Partial).unwrap(),
            "\"partial\""
        );
        assert_eq!(AuditOutcome::Failure.to_string(), "failure");
    }

    #[test]
    fn audit_error_kind_label_bounded() {
        assert_eq!(
            AuditError::WriteFailed {
                reason: "disk full".into()
            }
            .kind_label(),
            "write_failed"
        );
        assert_eq!(AuditError::Throttled.kind_label(), "throttled");
        assert_eq!(AuditError::Closed.kind_label(), "closed");
        assert_eq!(AuditError::Timeout.kind_label(), "timeout");
    }

    #[test]
    fn audit_error_display_includes_reason() {
        let err = AuditError::WriteFailed {
            reason: "EACCES".into(),
        };
        let s = err.to_string();
        assert!(s.contains("EACCES"));
    }

    #[test]
    fn audit_receipt_roundtrip_json() {
        let r = AuditReceipt {
            sink_id: "dev.mcpg.builtin.audit.local-file".into(),
            persisted_at: "2026-04-24T12:00:00.123Z".into(),
            durable_hash: "abc".repeat(21) + "d", // 64 hex chars
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: AuditReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, parsed);
    }

    #[test]
    fn audit_event_skip_serializing_if_hides_nones() {
        let event = AuditEvent {
            event_id: "id".into(),
            occurred_at: "t".into(),
            actor: sample_identity(),
            action: "a".into(),
            resource: None,
            outcome: AuditOutcome::Success,
            request_id: None,
            node_id: None,
            details: serde_json::json!({}),
            prev_event_hash: None,
        };
        let v: serde_json::Value = serde_json::to_value(&event).unwrap();
        assert!(v.get("resource").is_none());
        assert!(v.get("request_id").is_none());
        assert!(v.get("node_id").is_none());
        assert!(v.get("prev_event_hash").is_none());
    }
}
