//! `policy_engine` entity kind — centralised authorization
//! decisions (spec §9.14).
//!
//! Canonical engines: Open Policy Agent (OPA), AWS Cedar, Casbin,
//! custom Rego evaluators. Unlike `tool_gate` (binary allow/deny
//! per hook point), a policy engine provides richer decisions
//! (obligations the consumer must honour, redactions to apply to
//! the value flowing through) and is consulted by multiple entity
//! kinds at named *decision points*.
//!
//! # Composition
//!
//! Keyed by engine name. Multiple policy-engine entities can
//! coexist; consumers reference one by name. Registry supports
//! lookup by name, same shape as `transport` (keyed by self-
//! declared `name()`).
//!
//! # Decision points
//!
//! A decision point is a `dot.cased` identifier. The spec §9.14.1
//! defines the canonical set (`tool.call.pre`, `tool.call.post`,
//! `resource.read`, `http.route`, `admin.api`, ...). Operators +
//! plugins MAY define custom points; convention is to use a
//! plugin-owned prefix (e.g. `acme.billing.refund.approve`).
//!
//! # Side-effect contract
//!
//! Engines SHOULD be side-effect-free. An engine that also writes
//! to external systems violates the composability contract. Use
//! obligations + redactions to tell the consumer what to do; the
//! consumer decides whether + how to apply them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::manifest::PluginManifest;
use crate::types::PluginContext;

/// What an engine decides for a given `(decision_point, input)`
/// pair. `NotApplicable` lets engines decline gracefully — the
/// consumer falls back to its own default (or queries another
/// engine, if multiple are configured).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
    /// Engine doesn't govern this decision point. Consumer treats
    /// as "no policy applies" and falls back to its own defaults.
    NotApplicable,
}

impl PolicyEffect {
    /// Bounded metrics label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::NotApplicable => "not_applicable",
        }
    }
}

impl std::fmt::Display for PolicyEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Obligation the consumer MUST honour when the decision goes
/// through. Advisory from the engine's perspective but mandatory
/// for the consumer: a `tool_gate` consuming a policy engine MUST
/// emit the audit event a `"audit.emit"` obligation demands or
/// fail the request.
///
/// `kind` is a short identifier (`"audit.emit"`, `"notify.operator"`,
/// `"header.inject"`); `args` is the obligation-specific payload.
/// The interpretation contract lives in consumer documentation,
/// not in the engine — engines emit obligations they expect
/// consumers to recognise.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Obligation {
    pub kind: String,
    pub args: Value,
}

/// Redaction the consumer MUST apply to the value flowing through.
/// For `tool.call.post`, redactions apply to the result returned
/// to the client; for `tool.call.pre`, to the arguments the tool
/// receives. `json_pointer` is an RFC 6901 path into the value;
/// `replacement` is the value to substitute (usually `"***"` or
/// `null`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Redaction {
    pub json_pointer: String,
    pub replacement: Value,
}

/// Effective policy-document identifier at the time of a decision.
/// Audit sinks embed this so operators can reconstruct "which
/// policy version decided this request" long after the fact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyVersion {
    /// SHA-256 of the policy document (hex-encoded; `sha256:` prefix
    /// MAY be included for readability).
    pub hash: String,
    /// Wall-clock timestamp the engine loaded the current policy.
    /// RFC3339 string; keeps the protocol crate dep-free.
    pub loaded_at: String,
    /// Where the policy was loaded from (file path, git ref, OPA
    /// bundle URL, ...). Opaque to consumers; surfaced in audit.
    pub source: String,
}

/// The decision record the engine returns from `evaluate`. The
/// engine is trusted to populate `policy_version` at the time of
/// the decision — the consumer embeds it in audit events so a
/// future auditor can reconstruct "which policy decided this".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDecision {
    pub effect: PolicyEffect,
    #[serde(default)]
    pub obligations: Vec<Obligation>,
    #[serde(default)]
    pub redactions: Vec<Redaction>,
    /// Free-form attributes the engine surfaces (e.g. `tenant_id`,
    /// `risk_score`). Consumers MAY read for their own decisions
    /// but MUST NOT rely on specific keys.
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
    /// Human-readable explanation. Engines MAY omit; surfaced
    /// verbatim in Deny responses the consumer returns to the
    /// client. Redact-sensitive engines SHOULD leave this None
    /// for Allow decisions to keep attack-surface minimal.
    pub reason: Option<String>,
    /// Hash of the policy document that produced this decision.
    /// Echoes `PolicyEngine::policy_version().hash` at the time
    /// of evaluation.
    pub policy_version: String,
}

impl PolicyDecision {
    /// Shorthand for an Allow decision with no obligations /
    /// redactions / attributes. Most common shape.
    pub fn allow(policy_version: impl Into<String>) -> Self {
        Self {
            effect: PolicyEffect::Allow,
            obligations: Vec::new(),
            redactions: Vec::new(),
            attributes: BTreeMap::new(),
            reason: None,
            policy_version: policy_version.into(),
        }
    }

    /// Shorthand for a Deny decision with a reason.
    pub fn deny(reason: impl Into<String>, policy_version: impl Into<String>) -> Self {
        Self {
            effect: PolicyEffect::Deny,
            obligations: Vec::new(),
            redactions: Vec::new(),
            attributes: BTreeMap::new(),
            reason: Some(reason.into()),
            policy_version: policy_version.into(),
        }
    }

    /// Shorthand for NotApplicable — engine declines to decide.
    pub fn not_applicable(policy_version: impl Into<String>) -> Self {
        Self {
            effect: PolicyEffect::NotApplicable,
            obligations: Vec::new(),
            redactions: Vec::new(),
            attributes: BTreeMap::new(),
            reason: None,
            policy_version: policy_version.into(),
        }
    }
}

/// The `policy_engine` entity trait. Dispatched per-engine by
/// the gateway's registry.
///
/// Note `evaluate` returns `PolicyDecision` without a Result —
/// engines are expected to be side-effect-free and to represent
/// internal failures as `Deny` (with a `reason`) or
/// `NotApplicable`. This matches the spec §9.14 signature + keeps
/// consumers from having to encode error-vs-deny handling every
/// time they invoke a policy.
#[crate::async_trait]
pub trait PolicyEngine: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// Self-declared engine name (e.g. `"opa"`, `"cedar"`,
    /// `"yaml-rules"`). Registry refuses a duplicate plugin for
    /// the same name.
    fn name(&self) -> &str;

    /// Evaluate policy at a named decision point. `input` shape is
    /// defined per decision point (spec §9.14.1). `context`
    /// carries the request identity, request id, and MCP surface
    /// the decision is about.
    async fn evaluate(
        &self,
        decision_point: &str,
        input: &Value,
        context: &PluginContext,
    ) -> PolicyDecision;

    /// Return the policy document currently loaded by the engine.
    /// Used by consumers to stamp audit events with "policy
    /// version X decided this".
    async fn policy_version(&self) -> PolicyVersion;

    /// Called on gateway shutdown. Default is a no-op.
    async fn shutdown(&self) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effect_label_bounded() {
        assert_eq!(PolicyEffect::Allow.label(), "allow");
        assert_eq!(PolicyEffect::Deny.label(), "deny");
        assert_eq!(PolicyEffect::NotApplicable.label(), "not_applicable");
    }

    #[test]
    fn effect_display_matches_label() {
        assert_eq!(PolicyEffect::Allow.to_string(), "allow");
        assert_eq!(PolicyEffect::Deny.to_string(), "deny");
        assert_eq!(PolicyEffect::NotApplicable.to_string(), "not_applicable");
    }

    #[test]
    fn effect_serde_roundtrip() {
        let e = PolicyEffect::NotApplicable;
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(s, "\"not_applicable\"");
        let back: PolicyEffect = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn allow_decision_builder_is_clean() {
        let d = PolicyDecision::allow("sha256:abcd");
        assert_eq!(d.effect, PolicyEffect::Allow);
        assert_eq!(d.policy_version, "sha256:abcd");
        assert!(d.obligations.is_empty());
        assert!(d.redactions.is_empty());
        assert!(d.reason.is_none());
    }

    #[test]
    fn deny_decision_carries_reason() {
        let d = PolicyDecision::deny("admin requires mfa", "sha256:abcd");
        assert_eq!(d.effect, PolicyEffect::Deny);
        assert_eq!(d.reason.as_deref(), Some("admin requires mfa"));
    }

    #[test]
    fn not_applicable_decision_is_clean() {
        let d = PolicyDecision::not_applicable("sha256:abcd");
        assert_eq!(d.effect, PolicyEffect::NotApplicable);
    }

    #[test]
    fn decision_json_roundtrip_preserves_obligations_and_redactions() {
        let mut d = PolicyDecision::allow("sha256:v1");
        d.obligations.push(Obligation {
            kind: "audit.emit".into(),
            args: serde_json::json!({ "level": "high" }),
        });
        d.redactions.push(Redaction {
            json_pointer: "/ssn".into(),
            replacement: serde_json::json!("***"),
        });
        d.attributes
            .insert("tenant_id".into(), serde_json::json!("acme"));
        d.reason = Some("contains PII".into());
        let s = serde_json::to_string(&d).unwrap();
        let back: PolicyDecision = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn decision_json_missing_optional_fields_defaults_cleanly() {
        // Simulate a minimal engine response — only effect +
        // policy_version. serde(default) should fill the rest.
        let s = r#"{
            "effect": "allow",
            "reason": null,
            "policy_version": "sha256:v1"
        }"#;
        let d: PolicyDecision = serde_json::from_str(s).unwrap();
        assert_eq!(d.effect, PolicyEffect::Allow);
        assert!(d.obligations.is_empty());
        assert!(d.redactions.is_empty());
        assert!(d.attributes.is_empty());
    }

    #[test]
    fn policy_version_roundtrip() {
        let v = PolicyVersion {
            hash: "sha256:abcd".into(),
            loaded_at: "2026-04-23T10:00:00Z".into(),
            source: "file:/etc/policy.rego".into(),
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: PolicyVersion = serde_json::from_str(&s).unwrap();
        assert_eq!(v, back);
    }
}
