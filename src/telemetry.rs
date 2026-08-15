//! `telemetry_sink` entity kind — OTLP-shaped traces + metrics
//! export (spec §9.10).
//!
//! Canonical backends: OpenTelemetry Collector, Datadog, New Relic,
//! Honeycomb, Grafana Cloud. Fan-out composition — every registered
//! sink receives every event. Sinks MAY filter / sample / batch
//! internally; they MUST NOT block the request path.
//!
//! # Why its own entity kind (not just "log_sink with a kind field")
//!
//! Traces and metrics are span-shaped. Logs are line-shaped. The
//! span lifecycle (`span_started` → `span_ended`) has real
//! duration + relationship semantics that logs don't, and the OTLP
//! wire format encodes them very differently. Splitting the two
//! keeps each trait narrow + each sink implementation focused;
//! the shared `log_recorded` method on TelemetrySink is the
//! escape hatch for operators who want one vendor to receive
//! everything.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::manifest::PluginManifest;

/// Span kind — same semantics as the OTLP spec. `Internal` is the
/// default; the other variants carry network-boundary information
/// the backend uses to group traces.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SpanKind {
    Internal,
    Server,
    Client,
    Producer,
    Consumer,
}

/// Span status. `Error { message }` carries a short human-readable
/// reason; the `message` string is bounded-size (backends vary;
/// stay under 256 bytes to be safe).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpanStatus {
    Ok,
    Error {
        message: String,
    },
    /// Unset — the span completed but the sink should not interpret
    /// the outcome. Default for spans that don't represent a
    /// well-defined operation.
    Unset,
}

/// One event attached to a span (log-within-span pattern from OTel).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpanEvent {
    pub name: String,
    pub timestamp_ns: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

/// Span-started event. Sinks that want pairing state key on
/// `(trace_id, span_id)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpanStart {
    pub trace_id: String,
    pub span_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub name: String,
    pub kind: SpanKind,
    pub start_ns: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

/// Span-ended event. A sink that held state between Start + End
/// MUST tolerate the End never arriving (process crash, timeout).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpanEnd {
    pub trace_id: String,
    pub span_id: String,
    pub end_ns: u64,
    pub status: SpanStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<SpanEvent>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional_attributes: BTreeMap<String, serde_json::Value>,
}

/// Metric kind — matches OTLP instrument types.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    Counter,
    Gauge,
    Histogram,
}

/// Metric value. `Counter` / `Gauge` use `F64` or `I64` depending
/// on the plugin's intent; `Histogram` uses `HistogramValue` to
/// preserve bucket information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MetricValue {
    F64 {
        value: f64,
    },
    I64 {
        value: i64,
    },
    /// Histogram — carries a flat list of observed values. Sinks
    /// that need bucketed aggregates compute them downstream; the
    /// wire form stays simple.
    Histogram {
        count: u64,
        sum: f64,
        observations: Vec<f64>,
    },
}

/// One metric data point.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricPoint {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    pub kind: MetricKind,
    pub value: MetricValue,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    pub timestamp_ns: u64,
}

/// Telemetry-sink error. Used by `flush` + any variant of emit
/// that surfaces backend failures. Fan-out continues past
/// individual sink failures — backends translate native errors
/// into one of these so gateway policy is uniform.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryError {
    Backend { reason: String },
    Throttled,
    Closed,
    Timeout,
}

impl TelemetryError {
    /// Bounded metrics label.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Backend { .. } => "backend",
            Self::Throttled => "throttled",
            Self::Closed => "closed",
            Self::Timeout => "timeout",
        }
    }
}

impl std::fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend { reason } => write!(f, "telemetry backend: {reason}"),
            Self::Throttled => write!(f, "telemetry sink throttled"),
            Self::Closed => write!(f, "telemetry sink closed"),
            Self::Timeout => write!(f, "telemetry sink timeout"),
        }
    }
}

impl std::error::Error for TelemetryError {}

/// The `telemetry_sink` entity trait. Fan-out dispatch — every
/// registered sink receives every event the gateway's telemetry
/// emitter produces.
#[crate::async_trait]
pub trait TelemetrySink: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// Span started. Sinks that need pair-state key on
    /// `(trace_id, span_id)`.
    async fn span_started(&self, span: SpanStart);

    /// Span ended. Arrives at most once per span. Sinks MUST
    /// tolerate missing `span_ended` (crash, timeout) — the
    /// Start-without-End case is legitimate.
    async fn span_ended(&self, span: SpanEnd);

    /// Metric sample. Sinks that aggregate compute rollups
    /// downstream from these raw points.
    async fn metric_recorded(&self, metric: MetricPoint);

    /// Optional log pass-through for operators who want one vendor
    /// to receive every signal including logs. Default is a no-op;
    /// the canonical path for logs is the dedicated `log_sink`
    /// entity.
    async fn log_recorded(&self, record: &crate::logs::LogRecord) {
        let _ = record;
    }

    /// Force a flush. Called on graceful shutdown + periodically
    /// by the gateway's telemetry pipeline. `timeout` is a hint —
    /// exceeding it returns `TelemetryError::Timeout`.
    async fn flush(&self, timeout: Duration) -> Result<(), TelemetryError>;

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
    fn span_kind_snake_case_wire_format() {
        assert_eq!(
            serde_json::to_string(&SpanKind::Internal).unwrap(),
            "\"internal\""
        );
        assert_eq!(
            serde_json::to_string(&SpanKind::Server).unwrap(),
            "\"server\""
        );
    }

    #[test]
    fn span_status_error_carries_message() {
        let s = SpanStatus::Error {
            message: "deadline exceeded".into(),
        };
        let j = serde_json::to_value(&s).unwrap();
        assert_eq!(j["kind"], "error");
        assert_eq!(j["message"], "deadline exceeded");
    }

    #[test]
    fn metric_value_roundtrips_f64() {
        let v = MetricValue::F64 { value: 2.5 };
        let j = serde_json::to_string(&v).unwrap();
        let parsed: MetricValue = serde_json::from_str(&j).unwrap();
        assert_eq!(v, parsed);
    }

    #[test]
    fn metric_value_histogram_preserves_observations() {
        let v = MetricValue::Histogram {
            count: 3,
            sum: 6.0,
            observations: vec![1.0, 2.0, 3.0],
        };
        let j = serde_json::to_string(&v).unwrap();
        let parsed: MetricValue = serde_json::from_str(&j).unwrap();
        assert_eq!(v, parsed);
    }

    #[test]
    fn telemetry_error_kind_label_bounded() {
        assert_eq!(
            TelemetryError::Backend {
                reason: "EIO".into()
            }
            .kind_label(),
            "backend"
        );
        assert_eq!(TelemetryError::Throttled.kind_label(), "throttled");
        assert_eq!(TelemetryError::Closed.kind_label(), "closed");
        assert_eq!(TelemetryError::Timeout.kind_label(), "timeout");
    }
}
