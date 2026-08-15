//! `catalog_provider` entity kind — operator-curated tool discovery
//! metadata.
//!
//! Catalog providers are consulted on every `tools/list` request to
//! filter + enrich the raw tool descriptors built from binding
//! plugins. They flow operator-managed metadata (owners, tags,
//! documentation links, approval requirements, trust levels, sample
//! arguments) through to AI clients via MCP `_meta` annotations.
//!
//! # Composition
//!
//! Chain-bound. Operators bind one or more catalog providers in
//! `plugins[]` order; the gateway walks the chain and each
//! provider receives the previous provider's output as
//! `Vec<EnrichedToolDescriptor>`. Each provider refines the
//! in-progress view following the merge rules in
//! [`merge_into_existing`].
//!
//! # Merge rules
//!
//! - Scalar fields (`owner`, `doc_url`, `sample_arguments`,
//!   `trust_required`, `requires_approval`, `maturity`):
//!   first-write-wins. Earlier providers in the chain are
//!   authoritative; later providers fill gaps.
//! - `tags`: union across providers, deduplicated.
//! - `attributes` map: per-key first-write-wins.
//! - `hide`: OR across providers — any provider can drop a tool;
//!   downstream providers don't see hidden tools and can't re-add.
//!
//! # Side-effect contract
//!
//! Catalog providers SHOULD be side-effect-free. Each call returns a
//! refined view of the input. A catalog plugin that writes to
//! external systems (e.g. logs each tools/list invocation) violates
//! the composability contract and will hurt p99 latency.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::manifest::PluginManifest;
use crate::types::PluginContext;

// ---------------------------------------------------------------------------
// Tool descriptor as seen by catalog providers
// ---------------------------------------------------------------------------

/// Tool descriptor as it crosses the plugin boundary into a catalog
/// provider. Mirrors the gateway's internal `ToolDescriptor`
/// (`apps/gateway/src/bindings/mod.rs`) — only fields catalog
/// providers may need to inspect are surfaced here.
///
/// Catalog providers MAY read these fields for filtering decisions
/// (e.g. drop tools whose `name` matches a deny-list pattern) but
/// MUST NOT mutate them — the gateway's binding registry is the
/// source of truth for what a tool is. Providers refine
/// presentation metadata (the `catalog` field on
/// [`EnrichedToolDescriptor`]), not the underlying tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolToolDescriptor {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub description: String,
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
}

// ---------------------------------------------------------------------------
// Catalog metadata + enriched descriptor
// ---------------------------------------------------------------------------

/// Operator-supplied catalog metadata for a single tool. Surfaced
/// to AI clients via MCP `_meta.mcpg.catalog` annotations on
/// `tools/list` responses.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogMetadata {
    /// Free-form tags. Operators use these for catalog filtering
    /// in admin UIs + for policy decisions ("only allow tools
    /// tagged `read-only` from this caller").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Owning team / contact. Free-form string; convention is
    /// `team-name <email>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,

    /// External documentation URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc_url: Option<String>,

    /// Operator-supplied sample arguments (JSON object) showing a
    /// typical invocation. Helpful for AI clients building
    /// few-shot examples.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_arguments: Option<Value>,

    /// Minimum trust level the caller must have. Catalog providers
    /// MAY drop tools whose `trust_required` exceeds the caller's
    /// `identity.trust_level`. Values: `"verified"` |
    /// `"header_asserted"` | `"anonymous"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_required: Option<String>,

    /// Indicates the tool requires human approval before execution.
    /// Surfaced as an MCP annotation so AI clients can warn users.
    /// Actual approval enforcement is the `tool_gate.human-approval`
    /// plugin's job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,

    /// Maturity tag — `"experimental"` / `"beta"` / `"stable"` /
    /// `"deprecated"`. AI clients with rich UI MAY render badges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maturity: Option<String>,

    /// Free-form key/value extension attributes. Reserved for
    /// catalog-source-specific metadata (e.g. Backstage entity
    /// references, Confluence page IDs) downstream tools may want.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

impl CatalogMetadata {
    /// Returns `true` if the metadata carries no enrichment.
    /// Used by the gateway to decide whether to attach the
    /// `_meta.mcpg.catalog` annotation at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
            && self.owner.is_none()
            && self.doc_url.is_none()
            && self.sample_arguments.is_none()
            && self.trust_required.is_none()
            && self.requires_approval.is_none()
            && self.maturity.is_none()
            && self.attributes.is_empty()
    }

    /// Merge `incoming` into `self` following the chain merge rules:
    ///
    /// - Scalar fields (`owner`, `doc_url`, `sample_arguments`,
    ///   `trust_required`, `requires_approval`, `maturity`):
    ///   first-write-wins — `self` is authoritative; `incoming` only
    ///   fills gaps.
    /// - `tags`: union; `incoming`'s tags are appended after dedup.
    /// - `attributes`: per-key first-write-wins.
    pub fn merge_from(&mut self, incoming: &CatalogMetadata) {
        if self.owner.is_none() {
            self.owner.clone_from(&incoming.owner);
        }
        if self.doc_url.is_none() {
            self.doc_url.clone_from(&incoming.doc_url);
        }
        if self.sample_arguments.is_none() {
            self.sample_arguments.clone_from(&incoming.sample_arguments);
        }
        if self.trust_required.is_none() {
            self.trust_required.clone_from(&incoming.trust_required);
        }
        if self.requires_approval.is_none() {
            self.requires_approval = incoming.requires_approval;
        }
        if self.maturity.is_none() {
            self.maturity.clone_from(&incoming.maturity);
        }
        for tag in &incoming.tags {
            if !self.tags.contains(tag) {
                self.tags.push(tag.clone());
            }
        }
        for (k, v) in &incoming.attributes {
            self.attributes
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }
    }
}

/// Tool descriptor enriched with catalog-managed metadata. Flows
/// through `tools/list` to AI clients via MCP `_meta` annotations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrichedToolDescriptor {
    /// The original tool descriptor — name, description, schema.
    /// Fields here MUST exactly match the input from the binding
    /// registry to avoid breaking AI client expectations.
    #[serde(flatten)]
    pub base: ProtocolToolDescriptor,

    /// Catalog metadata. `None` until the first chain provider sets
    /// any field. Absent fields are omitted from the MCP `_meta`
    /// annotation by the gateway serializer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<CatalogMetadata>,
}

impl EnrichedToolDescriptor {
    /// Construct an `EnrichedToolDescriptor` from a raw
    /// `ProtocolToolDescriptor` with no catalog metadata. The
    /// gateway uses this to seed the chain input.
    #[must_use]
    pub fn from_base(base: ProtocolToolDescriptor) -> Self {
        Self {
            base,
            catalog: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Operator-facing catalog entry (forward-compat for a future admin API)
// ---------------------------------------------------------------------------

/// Operator-facing catalog entry — superset of
/// [`EnrichedToolDescriptor`]. Returned by `describe` +
/// `list_catalog`. Carries metadata operators see in admin endpoints
/// but doesn't expose to AI clients.
///
/// **v0.1 status:** the gateway does NOT expose any HTTP endpoint
/// built on `describe` / `list_catalog`. The methods are part of the
/// trait so plugins are forward-compatible when an admin API is
/// added.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogEntry {
    pub tool_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub catalog: CatalogMetadata,

    /// Per-tool access policy summary — descriptive, not enforced.
    /// E.g. "Read-only access for everyone in the `dev` group".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_summary: Option<String>,

    /// Last invocation timestamp from the gateway's audit data.
    /// Operator-side; not surfaced to AI clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_invoked_at: Option<String>,

    /// Invocation count over the last 30 days. Same source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent_invocations: Option<u64>,
}

// ---------------------------------------------------------------------------
// Trust level helpers
// ---------------------------------------------------------------------------

/// Canonical trust levels recognised by `trust_required`. Higher
/// position = stronger trust. A caller's `identity.trust_level` MUST
/// be at least at the required level for the tool to be visible.
pub const TRUST_LEVEL_VERIFIED: &str = "verified";
pub const TRUST_LEVEL_HEADER_ASSERTED: &str = "header_asserted";
pub const TRUST_LEVEL_ANONYMOUS: &str = "anonymous";

/// Compare two trust levels. Returns `true` if `caller` meets or
/// exceeds `required`. Unknown trust levels never satisfy a known
/// requirement (fail-closed).
#[must_use]
pub fn trust_level_meets(caller: &str, required: &str) -> bool {
    let caller_rank = trust_level_rank(caller);
    let required_rank = trust_level_rank(required);
    match (caller_rank, required_rank) {
        (Some(c), Some(r)) => c >= r,
        _ => false,
    }
}

fn trust_level_rank(level: &str) -> Option<u8> {
    match level {
        TRUST_LEVEL_ANONYMOUS => Some(0),
        TRUST_LEVEL_HEADER_ASSERTED => Some(1),
        TRUST_LEVEL_VERIFIED => Some(2),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Async trait
// ---------------------------------------------------------------------------

/// Catalog provider — filters + enriches `tools/list` results with
/// operator-curated metadata.
///
/// See module-level docs for composition + merge rules.
#[async_trait::async_trait]
pub trait CatalogProvider: Send + Sync {
    /// Plugin manifest. The gateway uses this for capability checks +
    /// observability.
    fn manifest(&self) -> &PluginManifest;

    /// Called on every `tools/list` request, once per bound catalog
    /// provider in chain order. The first provider in the chain
    /// receives the raw tool list wrapped as `EnrichedToolDescriptor`
    /// with `catalog: None`; subsequent providers receive the
    /// previous provider's output.
    ///
    /// Implementations:
    ///
    /// - MAY drop tools entirely. Hidden tools stay hidden — they
    ///   don't appear in the output and downstream providers don't
    ///   see them. This is the OR-merge semantic for `hide`.
    /// - MAY enrich tool metadata. MUST follow the merge rules in
    ///   the module docs: scalar fields are first-write-wins; tags
    ///   union; attributes per-key first-write-wins.
    /// - MUST NOT add tools that weren't in the input. The gateway's
    ///   binding registry is the source of truth; catalog providers
    ///   curate from that set, never invent.
    /// - SHOULD be fast. `tools/list` is on the AI-client startup
    ///   hot path; p99 < 10ms expected for config-driven plugins,
    ///   p99 < 100ms for external-source plugins.
    async fn filter_and_enrich(
        &self,
        ctx: &PluginContext,
        in_progress: &[EnrichedToolDescriptor],
    ) -> Vec<EnrichedToolDescriptor>;

    /// Forward-compat for a future admin API: full catalog
    /// metadata for one tool. v0.1 does NOT expose this via any
    /// HTTP endpoint.
    async fn describe(&self, tool_id: &str) -> Option<CatalogEntry>;

    /// Forward-compat for a future admin API: full catalog
    /// listing across the bound providers. Same v0.1 status as
    /// `describe`.
    async fn list_catalog(&self) -> Vec<CatalogEntry>;

    /// Optional graceful shutdown hook.
    async fn shutdown(&self) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn meta_with(owner: Option<&str>, tags: &[&str]) -> CatalogMetadata {
        CatalogMetadata {
            owner: owner.map(String::from),
            tags: tags.iter().map(|s| (*s).to_owned()).collect(),
            ..CatalogMetadata::default()
        }
    }

    #[test]
    fn empty_metadata_reports_empty() {
        assert!(CatalogMetadata::default().is_empty());
        assert!(!meta_with(Some("x"), &[]).is_empty());
        assert!(!meta_with(None, &["t"]).is_empty());
    }

    #[test]
    fn merge_first_write_wins_for_scalars() {
        let mut existing = meta_with(Some("team-a <a@x>"), &[]);
        let incoming = meta_with(Some("team-b <b@x>"), &[]);
        existing.merge_from(&incoming);
        assert_eq!(existing.owner.as_deref(), Some("team-a <a@x>"));
    }

    #[test]
    fn merge_fills_scalar_gap() {
        let mut existing = CatalogMetadata::default();
        let incoming = meta_with(Some("team-b"), &[]);
        existing.merge_from(&incoming);
        assert_eq!(existing.owner.as_deref(), Some("team-b"));
    }

    #[test]
    fn merge_unions_tags_and_dedupes() {
        let mut existing = meta_with(None, &["a", "b"]);
        let incoming = meta_with(None, &["b", "c"]);
        existing.merge_from(&incoming);
        assert_eq!(
            existing.tags,
            vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]
        );
    }

    #[test]
    fn merge_attributes_first_write_wins_per_key() {
        let mut existing = CatalogMetadata::default();
        existing
            .attributes
            .insert("k1".into(), "from-existing".into());
        let mut incoming = CatalogMetadata::default();
        incoming
            .attributes
            .insert("k1".into(), "from-incoming".into());
        incoming
            .attributes
            .insert("k2".into(), "from-incoming".into());
        existing.merge_from(&incoming);
        assert_eq!(
            existing.attributes.get("k1"),
            Some(&"from-existing".to_owned())
        );
        assert_eq!(
            existing.attributes.get("k2"),
            Some(&"from-incoming".to_owned())
        );
    }

    #[test]
    fn enriched_descriptor_roundtrips() {
        let descriptor = EnrichedToolDescriptor {
            base: ProtocolToolDescriptor {
                name: "orders.search".into(),
                title: None,
                description: "Search orders".into(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
            },
            catalog: Some(CatalogMetadata {
                tags: vec!["read-only".into()],
                owner: Some("team-a".into()),
                ..CatalogMetadata::default()
            }),
        };
        let json = serde_json::to_value(&descriptor).unwrap();
        assert_eq!(json["name"], "orders.search");
        assert_eq!(json["catalog"]["tags"][0], "read-only");
        let roundtrip: EnrichedToolDescriptor = serde_json::from_value(json).unwrap();
        assert_eq!(roundtrip, descriptor);
    }

    #[test]
    fn enriched_descriptor_omits_empty_catalog() {
        let descriptor = EnrichedToolDescriptor::from_base(ProtocolToolDescriptor {
            name: "orders.search".into(),
            title: None,
            description: "Search orders".into(),
            input_schema: json!({}),
            output_schema: None,
        });
        let json = serde_json::to_value(&descriptor).unwrap();
        assert!(json.get("catalog").is_none());
    }

    #[test]
    fn trust_level_meets_handles_canonical_levels() {
        assert!(trust_level_meets(
            TRUST_LEVEL_VERIFIED,
            TRUST_LEVEL_HEADER_ASSERTED
        ));
        assert!(trust_level_meets(
            TRUST_LEVEL_VERIFIED,
            TRUST_LEVEL_VERIFIED
        ));
        assert!(!trust_level_meets(
            TRUST_LEVEL_HEADER_ASSERTED,
            TRUST_LEVEL_VERIFIED
        ));
        assert!(!trust_level_meets(
            TRUST_LEVEL_ANONYMOUS,
            TRUST_LEVEL_HEADER_ASSERTED
        ));
    }

    #[test]
    fn trust_level_meets_fails_closed_on_unknown_levels() {
        assert!(!trust_level_meets("alien", TRUST_LEVEL_VERIFIED));
        assert!(!trust_level_meets(TRUST_LEVEL_VERIFIED, "alien"));
    }
}
