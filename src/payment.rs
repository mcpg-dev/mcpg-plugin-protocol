//! Shared payment types for protocol-aware payment plugins.
//!
//! These types are optional — a payment plugin can implement `ToolGatePlugin`
//! without implementing `PaymentAwarePlugin`. The `PaymentAwarePlugin` trait
//! enables protocol advertisement and capability negotiation.

use serde::{Deserialize, Serialize};

use crate::traits::ToolGatePlugin;

// ---------------------------------------------------------------------------
// Payment Protocol
// ---------------------------------------------------------------------------

/// Identifies a payment protocol.
///
/// Protocol identifiers are stable strings used in configuration and
/// capability advertisement.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentProtocol {
    /// Machine Payment Protocol (Tempo + Stripe).
    /// IETF draft-httpauth-payment-00.
    Mpp,
    /// Universal Commerce Protocol (Google + Shopify consortium).
    /// Full commerce lifecycle with checkout sessions.
    Ucp,
    /// Agentic Commerce Protocol (OpenAI + Stripe).
    /// REST checkout sessions with payment handlers.
    Acp,
    /// x402 Protocol (Coinbase).
    /// Simple crypto micropayments.
    X402,
    /// Custom protocol provided by a third-party plugin.
    #[serde(untagged)]
    Custom(String),
}

impl std::fmt::Display for PaymentProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mpp => write!(f, "mpp"),
            Self::Ucp => write!(f, "ucp"),
            Self::Acp => write!(f, "acp"),
            Self::X402 => write!(f, "x402"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

// ---------------------------------------------------------------------------
// Payment Capability
// ---------------------------------------------------------------------------

/// Describes the payment capabilities a plugin provides.
///
/// Used for protocol advertisement in tool listings and capability
/// negotiation with clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCapability {
    /// Which protocol this plugin implements.
    pub protocol: PaymentProtocol,

    /// Supported payment methods within the protocol.
    /// Examples: `["tempo", "stripe"]` for MPP, `["checkout"]` for UCP.
    pub methods: Vec<String>,

    /// Whether this plugin supports session-based/streaming billing.
    pub supports_sessions: bool,

    /// Whether this plugin supports multi-item commerce (cart/checkout).
    pub supports_commerce: bool,

    /// The `_meta` key prefix this plugin reads credentials from.
    /// Examples: `"org.paymentauth/"` for MPP, `"ucp/"` for UCP.
    pub meta_prefix: String,
}

// ---------------------------------------------------------------------------
// Payment Category
// ---------------------------------------------------------------------------

/// Category of payment plugin.
///
/// Used to distinguish simple tool-gate plugins from full commerce
/// session plugins. Affects how the gateway presents capabilities
/// to clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentCategory {
    /// Per-tool-call payment gating (MPP, x402).
    /// Gateway is the merchant.
    ToolGate,
    /// Multi-step commerce facilitation (UCP, ACP).
    /// Gateway facilitates transactions with external merchants.
    Commerce,
}

// ---------------------------------------------------------------------------
// PaymentAwarePlugin trait
// ---------------------------------------------------------------------------

/// Extended trait for payment-aware gate plugins.
///
/// Implementors provide protocol metadata used for capability
/// advertisement and client negotiation. This trait is a
/// supertrait of `ToolGatePlugin` — all payment plugins must
/// also implement the gate evaluation methods.
///
/// This trait is optional: a payment plugin that only needs
/// pre/post-dispatch gating can implement `ToolGatePlugin` alone.
pub trait PaymentAwarePlugin: ToolGatePlugin {
    /// Returns the payment capabilities this plugin supports.
    fn payment_capabilities(&self) -> Vec<PaymentCapability>;

    /// Returns which `_meta` key prefixes this plugin understands.
    ///
    /// The gateway uses this to determine which plugin should handle
    /// a tool call when multiple payment plugins are registered.
    fn credential_meta_keys(&self) -> Vec<String>;

    /// Returns the payment category.
    fn payment_category(&self) -> PaymentCategory;

    /// Returns the tools this plugin has payment configuration for.
    ///
    /// Enables the gateway to annotate `tools/list` responses with
    /// payment requirements without calling `evaluate_pre_dispatch`.
    fn configured_tools(&self) -> Vec<String>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_protocol_display() {
        assert_eq!(PaymentProtocol::Mpp.to_string(), "mpp");
        assert_eq!(PaymentProtocol::Ucp.to_string(), "ucp");
        assert_eq!(PaymentProtocol::Acp.to_string(), "acp");
        assert_eq!(PaymentProtocol::X402.to_string(), "x402");
        assert_eq!(
            PaymentProtocol::Custom("my-proto".into()).to_string(),
            "my-proto"
        );
    }

    #[test]
    fn payment_protocol_serde_roundtrip() {
        let protocols = vec![
            PaymentProtocol::Mpp,
            PaymentProtocol::Ucp,
            PaymentProtocol::Acp,
            PaymentProtocol::X402,
        ];
        for proto in &protocols {
            let json = serde_json::to_string(proto).unwrap();
            let parsed: PaymentProtocol = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, proto);
        }
    }

    #[test]
    fn payment_capability_serde_roundtrip() {
        let cap = PaymentCapability {
            protocol: PaymentProtocol::Mpp,
            methods: vec!["tempo".into()],
            supports_sessions: true,
            supports_commerce: false,
            meta_prefix: "org.paymentauth/".into(),
        };
        let json = serde_json::to_string(&cap).unwrap();
        let parsed: PaymentCapability = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.protocol, PaymentProtocol::Mpp);
        assert_eq!(parsed.methods, vec!["tempo"]);
        assert!(parsed.supports_sessions);
        assert!(!parsed.supports_commerce);
    }

    #[test]
    fn payment_category_serde_roundtrip() {
        let cat = PaymentCategory::ToolGate;
        let json = serde_json::to_string(&cat).unwrap();
        let parsed: PaymentCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, PaymentCategory::ToolGate);

        let cat = PaymentCategory::Commerce;
        let json = serde_json::to_string(&cat).unwrap();
        let parsed: PaymentCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, PaymentCategory::Commerce);
    }
}
