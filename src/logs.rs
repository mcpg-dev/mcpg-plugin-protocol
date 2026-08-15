//! `log_sink` entity kind — structured line-shaped log emission
//! (spec §9.11).
//!
//! Distinct from `telemetry_sink` because:
//!
//!   - Logs are line-shaped; telemetry is span-shaped.
//!   - Durability contracts differ: logs SHOULD be best-effort;
//!     traces MAY be sampled; audit events (§9.12) MUST be durable.
//!   - Wire formats differ: logs serialize as JSON-per-line by
//!     convention; OTLP encodes spans differently.
//!
//! Fan-out composition — every registered sink receives every log
//! record. The gateway's own `tracing_subscriber` feeds its events
//! into this chain at the bridge layer; plugins that declare
//! `cap.host.structured_logging` feed into the same stream.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::manifest::PluginManifest;
use crate::types::PluginIdentity;

/// Log severity. Mirrors the `tracing` crate's Level enum with one
/// extra serde-friendly variant ordering.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trace => write!(f, "trace"),
            Self::Debug => write!(f, "debug"),
            Self::Info => write!(f, "info"),
            Self::Warn => write!(f, "warn"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// One log record. All optional correlation fields are skipped on
/// serialisation when None — keeps JSON output compact for the
/// common case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogRecord {
    pub timestamp_ns: u64,
    pub level: LogLevel,
    /// `tracing::Event::metadata().target()` — typically the
    /// module path (`"mcpg::runtime::session"`).
    pub target: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<PluginIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// `Some(_)` when the event originated in a plugin (carries
    /// the plugin's id); `None` for gateway-internal events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<String>,
}

/// Log-sink error. Kept symmetric with `TelemetryError` for
/// operator-config uniformity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LogError {
    Backend { reason: String },
    Throttled,
    Closed,
    Timeout,
}

impl LogError {
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

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend { reason } => write!(f, "log backend: {reason}"),
            Self::Throttled => write!(f, "log sink throttled"),
            Self::Closed => write!(f, "log sink closed"),
            Self::Timeout => write!(f, "log sink timeout"),
        }
    }
}

impl std::error::Error for LogError {}

/// The `log_sink` entity trait. Fan-out dispatch — every registered
/// sink receives every `emit` call the gateway's logging bridge
/// produces.
#[crate::async_trait]
pub trait LogSink: Send + Sync {
    fn manifest(&self) -> &PluginManifest;

    /// Emit a record. Best-effort — drop-on-overflow is acceptable
    /// behaviour for a log sink (the audit fan-out is where
    /// durability contracts live, per spec §9.12).
    async fn emit(&self, record: &LogRecord);

    /// Force a flush. Called on graceful shutdown + on admin
    /// demand. Returns `LogError::Timeout` if the sink can't drain
    /// within `timeout`.
    async fn flush(&self, timeout: Duration) -> Result<(), LogError>;

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
    fn log_level_ordering_is_severity_ascending() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn log_level_snake_case_wire_format() {
        assert_eq!(serde_json::to_string(&LogLevel::Info).unwrap(), "\"info\"");
        assert_eq!(LogLevel::Warn.to_string(), "warn");
    }

    #[test]
    fn log_record_skip_serializing_if_hides_nones() {
        let record = LogRecord {
            timestamp_ns: 1,
            level: LogLevel::Info,
            target: "mcpg".into(),
            message: "hello".into(),
            fields: BTreeMap::new(),
            span_id: None,
            trace_id: None,
            request_id: None,
            identity: None,
            node_id: None,
            plugin_id: None,
        };
        let v: serde_json::Value = serde_json::to_value(&record).unwrap();
        for key in [
            "span_id",
            "trace_id",
            "request_id",
            "identity",
            "node_id",
            "plugin_id",
            "fields",
        ] {
            assert!(v.get(key).is_none(), "{key} should be skipped");
        }
    }

    #[test]
    fn log_error_kind_label_bounded() {
        assert_eq!(
            LogError::Backend {
                reason: "eio".into()
            }
            .kind_label(),
            "backend"
        );
        assert_eq!(LogError::Throttled.kind_label(), "throttled");
        assert_eq!(LogError::Closed.kind_label(), "closed");
        assert_eq!(LogError::Timeout.kind_label(), "timeout");
    }
}
