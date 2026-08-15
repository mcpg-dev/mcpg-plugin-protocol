//! `credential_issuer` entity kind — per-request backend
//! credential issuance keyed on caller identity.
//!
//! Resolves a credential per-request based on `PluginIdentity` +
//! an operator-supplied target. Lets binding plugins authenticate
//! to backends as the actual caller (or as a per-caller-scoped
//! role) rather than as a shared service account.
//!
//! # URI scheme
//!
//! Operators reference issuers via the new `cred://` URI scheme:
//!
//! ```yaml
//! plugins:
//!   - id: dev.mcpg.backend.sql
//!     config:
//!       databases:
//!         orders:
//!           url: postgres://orders.svc:5432/orders
//!           username: "cred://vault-pg/orders-readonly"
//!           password: "cred://vault-pg/orders-readonly"
//! ```
//!
//! `cred://<plugin_id>/<target>` markers are NOT resolved at boot.
//! The gateway holds them as deferred markers and resolves
//! per-request based on the caller's identity. See [`CredRef`] for
//! the parsed form.
//!
//! # Caching
//!
//! The gateway-side cache is keyed by `(identity_hash, plugin_id,
//! target)`. Plugin returns explicit TTLs; the cache evicts at
//! `issued_at + ttl_seconds`. Cache lifetime is plugin-host-side,
//! not plugin-side — plugins do NOT cache.
//!
//! # Error mapping
//!
//! - `Backend` → 503 (upstream credential authority unreachable).
//! - `NotAuthorized` → 403 (caller doesn't map to a role).
//! - `Misconfigured` → 500 (operator-side error).
//! - `Throttled` → 503 with retry hint.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::manifest::PluginManifest;
use crate::types::PluginIdentity;

// ---------------------------------------------------------------------------
// Issued credential + error types
// ---------------------------------------------------------------------------

/// A credential issued by a `credential_issuer` plugin. Carries
/// the credential bytes plus an explicit TTL the gateway-side
/// cache uses to schedule eviction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuedCredential {
    /// The credential bytes for single-value credentials
    /// (Bearer token, password). Multi-part credentials populate
    /// `parts` instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,

    /// Multi-part credentials (e.g. STS returns access_key_id +
    /// secret_access_key + session_token). Keyed by part name;
    /// bindings consume by key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parts: BTreeMap<String, String>,

    /// Lifetime in seconds. Gateway-side cache evicts at
    /// `issued_at + ttl_seconds`. Plugin sets to honor the
    /// upstream system's TTL (Vault lease_duration, STS
    /// DurationSeconds, etc.). Cache layer enforces
    /// `min(plugin_ttl, max_cache_ttl)`.
    pub ttl_seconds: u64,

    /// Plugin-specific lease handle. When `Some`, `revoke` can
    /// use it to release the credential explicitly. Vault
    /// dynamic-DB returns this; STS / minted-JWT don't (no
    /// revocation API).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,

    /// RFC 3339 timestamp of issuance. Used by the cache for
    /// expiry calculation; also flows into audit.
    pub issued_at: String,

    /// Free-form metadata. Surfaced to the binding via the
    /// resolved-config + audit; plugins use for per-call
    /// observability (e.g. `vault.role: "orders-readonly"`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl IssuedCredential {
    /// Convenience constructor for single-value credentials.
    #[must_use]
    pub fn from_value(value: impl Into<String>, ttl_seconds: u64) -> Self {
        Self {
            value: Some(value.into()),
            parts: BTreeMap::new(),
            ttl_seconds,
            lease_id: None,
            issued_at: String::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Look up a part by name. For single-value credentials,
    /// passing the literal `"value"` returns the single value.
    #[must_use]
    pub fn part(&self, name: &str) -> Option<&str> {
        if name == "value" {
            self.value.as_deref()
        } else {
            self.parts.get(name).map(String::as_str)
        }
    }
}

/// Error surface for credential issuance + revocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialError {
    /// Upstream credential authority unreachable (Vault down,
    /// STS endpoint timeout). Gateway returns 503 to the caller.
    Backend { reason: String },
    /// Caller's identity doesn't map to any role per the plugin's
    /// mapping rules. Gateway returns 403 to the caller.
    NotAuthorized { reason: String },
    /// Operator config error (target unknown to plugin, etc.).
    /// Gateway returns 500 — operator-side issue.
    Misconfigured { reason: String },
    /// Upstream rate-limited the plugin. Gateway may retry with
    /// backoff before failing.
    Throttled { reason: String },
}

impl CredentialError {
    /// Bounded metrics label — matches the `CacheError::kind_label`
    /// pattern (free-form `reason` never hits Prometheus).
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Backend { .. } => "backend",
            Self::NotAuthorized { .. } => "not_authorized",
            Self::Misconfigured { .. } => "misconfigured",
            Self::Throttled { .. } => "throttled",
        }
    }

    /// HTTP status the gateway returns when this error surfaces
    /// to a caller via a request that triggered credential
    /// resolution.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Backend { .. } | Self::Throttled { .. } => 503,
            Self::NotAuthorized { .. } => 403,
            Self::Misconfigured { .. } => 500,
        }
    }
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend { reason } => write!(f, "backend: {reason}"),
            Self::NotAuthorized { reason } => write!(f, "not_authorized: {reason}"),
            Self::Misconfigured { reason } => write!(f, "misconfigured: {reason}"),
            Self::Throttled { reason } => write!(f, "throttled: {reason}"),
        }
    }
}

impl std::error::Error for CredentialError {}

// ---------------------------------------------------------------------------
// `cred://` URI scheme
// ---------------------------------------------------------------------------

/// Reserved prefix for credential URIs.
pub const CRED_SCHEME: &str = "cred://";

/// Parsed form of a `cred://<plugin_id>/<target>[#<part>]` URI.
///
/// - `plugin_id` is the registered `credential_issuer` plugin's
///   manifest id.
/// - `target` is plugin-specific (typically a Vault role name, an
///   AWS IAM role ARN, a JWT audience).
/// - `part` is the optional fragment selecting a specific field
///   from a multi-part credential. `None` selects
///   `IssuedCredential::value` (single-value credentials).
///   `Some("username")` selects `parts["username"]` for
///   credentials returning a username/password pair (Vault DB),
///   `Some("access_key_id")` for STS, etc.
///
/// Operators reference both fields of a Vault DB credential like:
///
/// ```yaml
/// username: "cred://vault-pg/orders-readonly#username"
/// password: "cred://vault-pg/orders-readonly#password"
/// ```
///
/// Both URIs share the same `(plugin_id, target)` cache key, so
/// the credential is issued once and the gateway substitutes both
/// fields from one cached `IssuedCredential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredRef {
    pub plugin_id: String,
    pub target: String,
    pub part: Option<String>,
}

impl CredRef {
    /// Try to parse a `cred://` URI. Returns `None` if the input
    /// doesn't start with `cred://` or is malformed.
    #[must_use]
    pub fn parse(uri: &str) -> Option<Self> {
        let rest = uri.strip_prefix(CRED_SCHEME)?;
        // Fragment first — `cred://plugin/target#part` → split on
        // `#` once before further parsing so the target doesn't
        // accidentally absorb the fragment.
        let (path, part) = match rest.split_once('#') {
            Some((p, frag)) if !frag.is_empty() => (p, Some(frag.to_owned())),
            Some((_, _)) => return None, // empty fragment — malformed
            None => (rest, None),
        };
        let (plugin_id, target) = path.split_once('/')?;
        if plugin_id.is_empty() || target.is_empty() {
            return None;
        }
        Some(Self {
            plugin_id: plugin_id.to_owned(),
            target: target.to_owned(),
            part,
        })
    }

    /// Render back to the canonical URI form.
    #[must_use]
    pub fn to_uri(&self) -> String {
        match &self.part {
            Some(p) => format!("{CRED_SCHEME}{}/{}#{p}", self.plugin_id, self.target),
            None => format!("{CRED_SCHEME}{}/{}", self.plugin_id, self.target),
        }
    }

    /// The cache key dimension (plugin_id, target). Two CredRefs
    /// that differ only in `part` map to the same cached
    /// `IssuedCredential`.
    #[must_use]
    pub fn cache_key(&self) -> (&str, &str) {
        (&self.plugin_id, &self.target)
    }
}

/// Returns `true` if `s` looks like a `cred://` URI. Cheaper than
/// full `CredRef::parse` when the caller only needs to know
/// whether it's a credential reference at all.
#[must_use]
pub fn is_cred_uri(s: &str) -> bool {
    s.starts_with(CRED_SCHEME)
}

/// The `${cred://` token opener.
/// Find the matching closing `}` for a `${` whose inner content starts at
/// `start`, respecting nesting and string literals. Mirrors the
/// `mcpg-expr` interpolation parser so backends that don't use that engine
/// recognize exactly the same `${…}` blocks.
fn find_matching_brace(s: &str, start: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 1i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut i = start;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Extract the inner `cred://…` URI from every `${cred://…}` token in `s`,
/// in order. A **bare** `cred://…` (not wrapped in `${}`) is NOT a
/// credential reference and is ignored: in the standardized grammar a
/// credential resolves only when an operator writes it as a `${cred://…}`
/// token in config. The block is matched nesting-aware and its inner text
/// trimmed, so `${ cred://… }` is recognized exactly as the `mcpg-expr`
/// engine recognizes it (the two grammars must agree). Backends that don't
/// use that engine use this to find their config-origin credential refs.
#[must_use]
pub fn cred_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$'
            && bytes[i + 1] == b'{'
            && let Some(end) = find_matching_brace(s, i + 2)
        {
            let inner = s[i + 2..end].trim();
            if inner.starts_with("cred://") {
                out.push(inner.to_owned());
            }
            i = end + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// Replace every `${cred://…}` token in `s` with its resolved value from
/// `resolved` (keyed by the inner, trimmed `cred://…` URI). Cred tokens
/// absent from the map, and non-credential `${…}` blocks, are left intact;
/// bare `cred://…` is never touched. Matches [`cred_tokens`]' grammar.
#[must_use]
pub fn substitute_cred_tokens(
    s: &str,
    resolved: &std::collections::HashMap<String, String>,
) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len()
            && bytes[i] == b'$'
            && bytes[i + 1] == b'{'
            && let Some(end) = find_matching_brace(s, i + 2)
        {
            let inner = s[i + 2..end].trim();
            if inner.starts_with("cred://") {
                match resolved.get(inner) {
                    Some(v) => out.push_str(v),
                    None => out.push_str(&s[i..=end]),
                }
            } else {
                // A non-credential `${…}` block (e.g. a CEL ref) — leave it
                // verbatim for the request-time layers.
                out.push_str(&s[i..=end]);
            }
            i = end + 1;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Identity hash (cache key dimension)
// ---------------------------------------------------------------------------

/// Compute a deterministic 256-bit hash of the caller's identity for
/// use as the cache key dimension.
///
/// By default excludes `attributes` — operator-side identity providers
/// may emit per-request attributes that would balloon cache
/// cardinality. Only stable, normalised fields
/// contribute. Operators whose `credential_issuer` derives its
/// principal from a token claim (e.g. a tenant id) must fold that
/// claim in via [`identity_hash_with_attrs`] so callers differing only
/// by the claim do not share a cached credential.
#[must_use]
pub fn identity_hash(identity: &PluginIdentity) -> String {
    identity_hash_with_attrs(identity, &[])
}

/// Like [`identity_hash`], but additionally folds an operator-designated,
/// allow-listed subset of `identity.attributes` into the digest so
/// callers that differ only by those claims (commonly the tenant claim)
/// get separate cache entries. An empty `key_attributes` is byte-identical
/// to [`identity_hash`].
///
/// Only PRESENT allow-listed keys contribute, keeping cardinality bounded
/// to the operator-chosen claim space. The digest is SHA-256 over a
/// length-prefixed encoding: each field is fed with its label and value
/// length so `(subject="a", issuer="b")` can never collide with
/// `(subject="ab", issuer="")`, and list lengths are fed so `["a","b"]`
/// can never collide with `["ab"]`. `None` and `Some("")` are equated.
#[must_use]
pub fn identity_hash_with_attrs(identity: &PluginIdentity, key_attributes: &[String]) -> String {
    use sha2::{Digest, Sha256};

    fn feed(h: &mut Sha256, label: &[u8], val: &str) {
        h.update((label.len() as u32).to_le_bytes());
        h.update(label);
        h.update((val.len() as u64).to_le_bytes());
        h.update(val.as_bytes());
    }

    let mut h = Sha256::new();
    h.update(b"mcpg.identity_hash.v2\0"); // domain separation
    feed(&mut h, b"kind", &identity.kind);
    feed(&mut h, b"trust_level", &identity.trust_level);
    feed(
        &mut h,
        b"subject_id",
        identity.subject_id.as_deref().unwrap_or(""),
    );
    feed(
        &mut h,
        b"auth_provider",
        identity.auth_provider.as_deref().unwrap_or(""),
    );
    feed(&mut h, b"issuer", identity.issuer.as_deref().unwrap_or(""));
    let mut roles = identity.roles.clone();
    roles.sort();
    let mut groups = identity.groups.clone();
    groups.sort();
    let mut scopes = identity.scopes.clone();
    scopes.sort();
    for (label, list) in [
        (&b"role"[..], &roles),
        (&b"group"[..], &groups),
        (&b"scope"[..], &scopes),
    ] {
        h.update((list.len() as u64).to_le_bytes());
        for item in list {
            feed(&mut h, label, item);
        }
    }
    // Fold only the present, allow-listed attributes, sorted by key so the
    // set canonicalizes regardless of insertion order.
    let mut attrs: Vec<(&str, &str)> = key_attributes
        .iter()
        .filter_map(|k| {
            identity
                .attributes
                .get_key_value(k.as_str())
                .map(|(k, v)| (k.as_str(), v.as_str()))
        })
        .collect();
    attrs.sort();
    h.update((attrs.len() as u64).to_le_bytes());
    for (k, v) in attrs {
        feed(&mut h, b"attr.k", k);
        feed(&mut h, b"attr.v", v);
    }
    hex::encode(h.finalize())
}

// ---------------------------------------------------------------------------
// Async trait
// ---------------------------------------------------------------------------

/// Credential issuer — issues per-request backend credentials
/// keyed on caller identity.
///
/// See module-level docs for URI scheme + caching semantics.
#[async_trait::async_trait]
pub trait CredentialIssuer: Send + Sync {
    /// Plugin manifest. The gateway uses this for capability
    /// checks + observability.
    fn manifest(&self) -> &PluginManifest;

    /// The credential KIND this issuer mints, used for kind-precise
    /// capability enforcement: a caller resolving a
    /// `cred://<this issuer>/<target>` reference must hold
    /// `CredentialIssue{ kinds: [<this kind>] }`.
    ///
    /// Defaults to the issuer's manifest id, so each issuer is its own
    /// kind and grants are per-issuer by default (least-privilege,
    /// enforceable with zero descriptor changes). An in-process or
    /// built-in issuer MAY override to a coarser shared kind (e.g.
    /// `"oauth_token"`) when several issuer instances should share one
    /// grant. NOTE: native cdylib issuers always use this default — the
    /// host's FFI adapter resolves `manifest()` but has no vtable slot
    /// for an override (the ABI is frozen at v1); a future slot can
    /// surface a plugin-declared kind without changing this contract.
    fn credential_kind(&self) -> String {
        self.manifest().id.clone()
    }

    /// Issue a credential for the given identity + target.
    ///
    /// `identity`: the calling principal. Plugins use the
    /// subject_id, roles, scopes, attributes per their config
    /// (e.g. map subject_id to Vault role).
    ///
    /// `target`: the operator-supplied target string from the
    /// `cred://<plugin_id>/<target>` URI. Plugin-specific
    /// semantics — typically a Vault role name, an AWS IAM
    /// role ARN, a JWT audience.
    ///
    /// `config`: this plugin's operator-supplied config. Same
    /// JSON the plugin received in `from_config_json` at boot;
    /// passed per-call so plugins reference per-target rules
    /// without rebuilding state.
    async fn issue(
        &self,
        identity: &PluginIdentity,
        target: &str,
        config: &Value,
    ) -> Result<IssuedCredential, CredentialError>;

    /// Optionally revoke a previously-issued credential. Default:
    /// no-op (for issuers that don't support explicit
    /// revocation). Vault DB issuer overrides to call
    /// `PUT /v1/sys/leases/revoke` so the database account
    /// flows back to Vault's pool.
    async fn revoke(&self, lease_id: &str) -> Result<(), CredentialError> {
        let _ = lease_id;
        Ok(())
    }

    /// Optional graceful shutdown hook.
    async fn shutdown(&self) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(subject: &str) -> PluginIdentity {
        PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: Some(subject.into()),
            auth_provider: Some("oidc".into()),
            issuer: Some("https://idp.example.com".into()),
            roles: vec!["dev".into()],
            groups: vec![],
            scopes: vec!["read".into()],
            attributes: BTreeMap::new(),
        }
    }

    #[test]
    fn cred_ref_parses_well_formed_uri() {
        let r = CredRef::parse("cred://vault-pg/orders-readonly").unwrap();
        assert_eq!(r.plugin_id, "vault-pg");
        assert_eq!(r.target, "orders-readonly");
        assert!(r.part.is_none());
        assert_eq!(r.to_uri(), "cred://vault-pg/orders-readonly");
    }

    #[test]
    fn cred_ref_parses_uri_with_fragment_part() {
        let r = CredRef::parse("cred://vault-pg/orders-readonly#username").unwrap();
        assert_eq!(r.plugin_id, "vault-pg");
        assert_eq!(r.target, "orders-readonly");
        assert_eq!(r.part.as_deref(), Some("username"));
        assert_eq!(r.to_uri(), "cred://vault-pg/orders-readonly#username");
    }

    #[test]
    fn cred_ref_same_target_different_part_share_cache_key() {
        let a = CredRef::parse("cred://p/t#username").unwrap();
        let b = CredRef::parse("cred://p/t#password").unwrap();
        assert_eq!(a.cache_key(), b.cache_key());
        assert_ne!(a.part, b.part);
    }

    #[test]
    fn cred_ref_rejects_malformed() {
        assert!(CredRef::parse("vault://x").is_none());
        assert!(CredRef::parse("cred://").is_none());
        assert!(CredRef::parse("cred:///target").is_none());
        assert!(CredRef::parse("cred://plugin").is_none());
        assert!(CredRef::parse("cred://plugin/").is_none());
        assert!(CredRef::parse("cred://plugin/target#").is_none()); // empty fragment
    }

    #[test]
    fn is_cred_uri_matches_prefix() {
        assert!(is_cred_uri("cred://x/y"));
        assert!(!is_cred_uri("vault://x/y"));
        assert!(!is_cred_uri("plain string"));
    }

    #[test]
    fn cred_tokens_extracts_only_wrapped_refs() {
        assert_eq!(
            cred_tokens("Bearer ${cred://oauth/api}"),
            vec!["cred://oauth/api"]
        );
        assert_eq!(
            cred_tokens("${cred://a/b} and ${cred://c/d#user}"),
            vec!["cred://a/b", "cred://c/d#user"]
        );
        // SECURITY: a BARE cred:// (not wrapped in ${}) is NOT a token.
        assert!(cred_tokens("Bearer cred://oauth/api").is_empty());
        assert!(cred_tokens("no creds here").is_empty());
    }

    #[test]
    fn cred_tokens_grammar_matches_expr_engine() {
        // Interior whitespace inside the braces is trimmed (parity with the
        // mcpg-expr parser), so a backend using this helper resolves the
        // same token the net-core engine does.
        assert_eq!(cred_tokens("${ cred://vault/db }"), vec!["cred://vault/db"]);
        // A non-credential ${…} block is ignored.
        assert!(cred_tokens("${arguments.x} ${env.Y}").is_empty());
        // The closing brace is matched nesting-aware, not at the first `}`.
        assert_eq!(
            cred_tokens("${cred://a/b#${arguments.x}}"),
            vec!["cred://a/b#${arguments.x}"]
        );
        // Trimmed whitespace token also substitutes.
        let mut map = std::collections::HashMap::new();
        map.insert("cred://vault/db".to_owned(), "PW".to_owned());
        assert_eq!(
            substitute_cred_tokens("u=${ cred://vault/db }", &map),
            "u=PW"
        );
    }

    #[test]
    fn substitute_cred_tokens_replaces_wrapped_leaves_bare() {
        let mut map = std::collections::HashMap::new();
        map.insert("cred://oauth/api".to_owned(), "TOKEN".to_owned());
        // Wrapped token resolved.
        assert_eq!(
            substitute_cred_tokens("Bearer ${cred://oauth/api}", &map),
            "Bearer TOKEN"
        );
        // SECURITY: bare cred:// is left verbatim (never resolved).
        assert_eq!(
            substitute_cred_tokens("Bearer cred://oauth/api", &map),
            "Bearer cred://oauth/api"
        );
        // Unknown token left intact.
        assert_eq!(
            substitute_cred_tokens("${cred://other/x}", &map),
            "${cred://other/x}"
        );
    }

    #[test]
    fn identity_hash_is_stable_for_same_identity() {
        let id = identity("alice");
        let h1 = identity_hash(&id);
        let h2 = identity_hash(&id);
        assert_eq!(h1, h2);
    }

    #[test]
    fn identity_hash_differs_for_different_subjects() {
        let h_alice = identity_hash(&identity("alice"));
        let h_bob = identity_hash(&identity("bob"));
        assert_ne!(h_alice, h_bob);
    }

    #[test]
    fn identity_hash_ignores_attribute_churn() {
        let mut alice_a = identity("alice");
        let mut alice_b = identity("alice");
        alice_a.attributes.insert("k".into(), "1".into());
        alice_b.attributes.insert("k".into(), "2".into());
        // Attributes excluded from hash (cardinality bound).
        assert_eq!(identity_hash(&alice_a), identity_hash(&alice_b));
    }

    #[test]
    fn identity_hash_normalises_role_order() {
        let mut a = identity("alice");
        let mut b = identity("alice");
        a.roles = vec!["dev".into(), "ops".into()];
        b.roles = vec!["ops".into(), "dev".into()];
        assert_eq!(identity_hash(&a), identity_hash(&b));
    }

    #[test]
    fn identity_hash_is_256_bit_hex() {
        let h = identity_hash(&identity("alice"));
        assert_eq!(h.len(), 64);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn identity_hash_field_boundaries_are_unambiguous() {
        // Length-prefixing must stop field/list concatenation collisions.
        let mut a = identity("alice");
        let mut b = identity("alice");
        a.roles = vec!["a".into(), "b".into()];
        b.roles = vec!["ab".into()];
        assert_ne!(identity_hash(&a), identity_hash(&b));

        let mut c = identity("a");
        c.issuer = Some("b".into());
        let mut d = identity("ab");
        d.issuer = Some("".into());
        assert_ne!(identity_hash(&c), identity_hash(&d));
    }

    #[test]
    fn identity_hash_distinguishes_role_vs_group() {
        let mut a = identity("alice");
        a.roles = vec!["x".into()];
        a.groups = vec![];
        let mut b = identity("alice");
        b.roles = vec![];
        b.groups = vec!["x".into()];
        assert_ne!(identity_hash(&a), identity_hash(&b));
    }

    #[test]
    fn identity_hash_empty_allowlist_equals_legacy() {
        let mut id = identity("alice");
        id.attributes.insert("tenant".into(), "acme".into());
        // The no-attribute helper and the default must be byte-identical so
        // an unset key_attributes never silently churns cache keys.
        assert_eq!(identity_hash_with_attrs(&id, &[]), identity_hash(&id));
    }

    #[test]
    fn identity_hash_with_attrs_partitions_on_allowlisted_attr() {
        let mut acme = identity("alice");
        acme.attributes.insert("tenant".into(), "acme".into());
        let mut beta = identity("alice");
        beta.attributes.insert("tenant".into(), "beta".into());
        let allow = vec!["tenant".to_string()];
        assert_ne!(
            identity_hash_with_attrs(&acme, &allow),
            identity_hash_with_attrs(&beta, &allow)
        );
        // With no allowlist the two share a key (documents the opt-in default).
        assert_eq!(identity_hash(&acme), identity_hash(&beta));
    }

    #[test]
    fn identity_hash_with_attrs_ignores_non_allowlisted_attr() {
        let mut a = identity("alice");
        a.attributes.insert("tenant".into(), "acme".into());
        a.attributes.insert("request_id".into(), "r1".into());
        let mut b = identity("alice");
        b.attributes.insert("tenant".into(), "acme".into());
        b.attributes.insert("request_id".into(), "r2".into());
        let allow = vec!["tenant".to_string()];
        assert_eq!(
            identity_hash_with_attrs(&a, &allow),
            identity_hash_with_attrs(&b, &allow)
        );
    }

    #[test]
    fn identity_hash_with_attrs_present_vs_absent_differ() {
        let mut present = identity("alice");
        present.attributes.insert("tenant".into(), "".into());
        let absent = identity("alice");
        let allow = vec!["tenant".to_string()];
        assert_ne!(
            identity_hash_with_attrs(&present, &allow),
            identity_hash_with_attrs(&absent, &allow)
        );
    }

    #[test]
    fn issued_credential_part_lookup() {
        let cred = IssuedCredential::from_value("token-xyz", 3600);
        assert_eq!(cred.part("value"), Some("token-xyz"));
        assert_eq!(cred.part("missing"), None);
    }

    #[test]
    fn credential_error_serializes_with_kind_tag() {
        let e = CredentialError::NotAuthorized {
            reason: "no role".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"kind\":\"not_authorized\""));
    }
}
