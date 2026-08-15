//! `metrics_sink` entity kind — gateway metric event delivery.
//!
//! Distinct from `telemetry_sink` because:
//!
//!   - Telemetry is span-shaped + OTLP-coded; metrics flow through
//!     the `metrics-rs` recorder API and are pull/push agnostic.
//!   - Sink composition differs: every metric goes to every metrics
//!     sink (fan-out); a metric-only Prometheus sink doesn't need
//!     to implement no-op span methods just to receive counters.
//!   - Operator config is per-signal: `observability.metrics.sinks`
//!     drives this entity, `observability.traces.sinks` drives
//!     telemetry, `observability.logs.sinks` drives logs.
//!
//! `TelemetrySink::metric_recorded` is the legacy single-trait
//! convenience for OTLP-sink authors who want one trait that
//! receives spans + metrics (the OTel data model). Operators
//! wiring an OTLP plugin via `observability.traces.sinks: [{kind:
//! dev.mcpg.observability.otlp}]` get spans through that path; if
//! they ALSO want metrics through the same plugin, list the same
//! kind under `observability.metrics.sinks` and let the plugin
//! implement both `TelemetrySink` and `MetricsSink`.
//!
//! Reuses [`MetricPoint`] (and its [`MetricKind`] / [`MetricValue`])
//! from [`crate::telemetry`] — no point duplicating the wire shape
//! across two modules.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::manifest::PluginManifest;
pub use crate::telemetry::{MetricKind, MetricPoint, MetricValue};

/// Metrics-sink error. Symmetric with [`crate::logs::LogError`] +
/// [`crate::telemetry::TelemetryError`] for operator-config
/// uniformity. Backends translate native errors into one of these
/// so gateway policy is uniform.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MetricsError {
    Backend { reason: String },
    Throttled,
    Closed,
    Timeout,
}

impl MetricsError {
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

impl std::fmt::Display for MetricsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend { reason } => write!(f, "metrics backend: {reason}"),
            Self::Throttled => write!(f, "metrics sink throttled"),
            Self::Closed => write!(f, "metrics sink closed"),
            Self::Timeout => write!(f, "metrics sink timeout"),
        }
    }
}

impl std::error::Error for MetricsError {}

/// The `metrics_sink` entity trait. Fan-out dispatch — every
/// registered sink receives every `emit` call the gateway's metrics
/// pipeline produces.
///
/// Sinks MAY filter / aggregate / batch internally; they MUST NOT
/// block the request path. A counter increment on the hot path
/// fires-and-forgets — the metrics pipeline owns the bounded
/// queue + drop-on-overflow semantics, sinks own only delivery.
#[crate::async_trait]
pub trait MetricsSink: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// Emit one metric data point. Best-effort — drop-on-overflow
    /// is acceptable behaviour for a metrics sink. Sinks that need
    /// rollups compute them from these raw samples.
    async fn emit(&self, metric: &MetricPoint);

    /// Force a flush. Called on graceful shutdown + on admin
    /// demand. Returns [`MetricsError::Timeout`] if the sink can't
    /// drain within `timeout`.
    async fn flush(&self, timeout: Duration) -> Result<(), MetricsError>;

    /// Optional textual snapshot of the sink's current state.
    /// Pull-style metrics sinks (Prometheus exposition
    /// at `/metrics`) override this to return their content-typed
    /// payload — `text/plain; version=0.0.4` for the canonical
    /// Prometheus plugin. Push-only sinks (OTLP, Datadog) keep the
    /// `None` default; the gateway then short-circuits the
    /// `/metrics` route to a 404.
    async fn render_text_exposition(&self) -> Option<String> {
        None
    }

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
    fn metrics_error_kind_label_bounded() {
        assert_eq!(
            MetricsError::Backend {
                reason: "EIO".into()
            }
            .kind_label(),
            "backend"
        );
        assert_eq!(MetricsError::Throttled.kind_label(), "throttled");
        assert_eq!(MetricsError::Closed.kind_label(), "closed");
        assert_eq!(MetricsError::Timeout.kind_label(), "timeout");
    }

    #[test]
    fn metrics_error_display_includes_reason() {
        let e = MetricsError::Backend {
            reason: "scrape endpoint refused".into(),
        };
        assert!(
            e.to_string().contains("scrape endpoint refused"),
            "display dropped reason: {e}"
        );
    }

    #[test]
    fn metric_point_types_re_exported_from_telemetry() {
        // Compile-time sanity: the re-exported types resolve through
        // crate::metrics:: and round-trip a serde edge case
        // (Histogram observations).
        let v = MetricValue::Histogram {
            count: 2,
            sum: 5.0,
            observations: vec![2.0, 3.0],
        };
        let j = serde_json::to_string(&v).unwrap();
        let parsed: MetricValue = serde_json::from_str(&j).unwrap();
        assert_eq!(v, parsed);
    }
}
