//! A short, stable fingerprint of the plugin ABI's type layout.
//!
//! [`crate::abi::MCPG_PLUGIN_ABI_VERSION`] stays fixed while layouts change in
//! place, so two incompatible builds report the same version, and the host
//! refuses the mismatch only at load, in `check_layout_compatibility`. The
//! fingerprint names a layout without loading anything: the host reports its
//! own (`mcpg capabilities`), a packaged plugin records the one it was
//! packaged with, and two different fingerprints predict that refusal.
//!
//! It hashes, for every type the layout reaches, what that check compares:
//! the full type name, size, alignment, `repr`, non-zero niche and the shape
//! of the data — primitive kind, struct and union fields, enum variants and
//! discriminants, prefix-type fields — with each field's type name and the
//! signatures of its function pointers. It leaves out what changes with every
//! release while the layout stays the same: package versions, source lines,
//! module paths and the compiler's type ids.

use std::collections::{BTreeSet, HashSet};
use std::fmt::Write as _;

use abi_stable::StableAbi;
use abi_stable::type_layout::{TLData, TLFields, TypeLayout};
use sha2::{Digest, Sha256};

use crate::abi::PluginRegistration;

/// The fingerprint of `layout` and of every type it reaches: `sha256:` and
/// the first 16 bytes of the digest, in hex.
///
/// The layouts reached are the ones `abi_stable` itself traverses — each
/// layout's shared type layouts, which hold its fields' types and its
/// function pointers' parameter and return types. Each is described on its
/// own, and the descriptions are hashed sorted, so the traversal order does
/// not matter.
#[must_use]
pub fn layout_fingerprint(layout: &'static TypeLayout) -> String {
    let mut seen = HashSet::new();
    let mut todo = vec![layout];
    let mut described = BTreeSet::new();
    while let Some(l) = todo.pop() {
        if !seen.insert(l.get_utypeid()) {
            continue;
        }
        described.insert(describe(l));
        todo.extend(l.shared_vars().type_layouts().iter().map(|nested| nested()));
    }
    let mut hasher = Sha256::new();
    for d in &described {
        hasher.update(d.as_bytes());
        hasher.update(b"\n");
    }
    let digest = hasher.finalize();
    let mut out = String::from("sha256:");
    for b in &digest[..16] {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The fingerprint of the [`PluginRegistration`] layout this build of the
/// protocol defines: the host's, and that of every plugin built from the same
/// protocol source.
#[must_use]
pub fn plugin_abi_layout_fingerprint() -> String {
    layout_fingerprint(<PluginRegistration as StableAbi>::LAYOUT)
}

fn describe(l: &'static TypeLayout) -> String {
    let mut d = format!(
        "{}|size={}|align={}|repr={:?}|nonzero={}|",
        l.full_type(),
        l.size(),
        l.alignment(),
        l.repr_attr(),
        l.is_nonzero(),
    );
    match l.data() {
        TLData::Primitive(p) => {
            let _ = write!(d, "primitive {p:?}");
        }
        TLData::Opaque => d.push_str("opaque"),
        TLData::Struct { fields } => {
            d.push_str("struct");
            push_fields(&mut d, fields);
        }
        TLData::Union { fields } => {
            d.push_str("union");
            push_fields(&mut d, fields);
        }
        TLData::Enum(e) => {
            let _ = write!(
                d,
                "enum variants={} counts={:?} discriminants={:?} exhaustive={:?}",
                e.variant_names, e.field_count, e.discriminants, e.exhaustiveness,
            );
            push_fields(&mut d, e.fields);
        }
        TLData::PrefixType(p) => {
            let _ = write!(
                d,
                "prefix first_suffix={} conditional={:?}",
                p.first_suffix_field, p.conditional_prefix_fields,
            );
            push_fields(&mut d, p.fields);
        }
    }
    let phantom = l.phantom_fields();
    if !phantom.is_empty() {
        d.push_str("|phantom");
        push_fields(&mut d, phantom);
    }
    if let Some(extra) = l.extra_checks() {
        let _ = write!(d, "|extra={extra}");
    }
    d
}

fn push_fields(d: &mut String, fields: TLFields) {
    for f in fields.iter() {
        let _ = write!(d, " {}:{}", f.name(), f.full_type());
        for func in f.function_range() {
            let _ = write!(d, "[{func}]");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fingerprint_is_a_stable_digest() {
        let fp = plugin_abi_layout_fingerprint();
        assert_eq!(
            fp,
            plugin_abi_layout_fingerprint(),
            "two computations agree"
        );
        let hex = fp.strip_prefix("sha256:").expect("sha256: prefix");
        assert_eq!(hex.len(), 32);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn a_different_layout_has_a_different_fingerprint() {
        #[repr(C)]
        #[derive(StableAbi)]
        struct Narrow {
            a: u32,
        }
        #[repr(C)]
        #[derive(StableAbi)]
        struct Wide {
            a: u64,
        }
        assert_ne!(
            layout_fingerprint(<Narrow as StableAbi>::LAYOUT),
            layout_fingerprint(<Wide as StableAbi>::LAYOUT),
        );
        assert_ne!(
            layout_fingerprint(<Narrow as StableAbi>::LAYOUT),
            plugin_abi_layout_fingerprint(),
        );
    }

    #[test]
    fn a_renamed_field_changes_the_fingerprint() {
        #[repr(C)]
        #[derive(StableAbi)]
        struct Before {
            calls: u32,
        }
        #[repr(C)]
        #[derive(StableAbi)]
        struct After {
            count: u32,
        }
        // Different type names would differ anyway; the field name is what
        // this compares, so both carry it under one wrapper name.
        let before = describe(<Before as StableAbi>::LAYOUT).replace("Before", "T");
        let after = describe(<After as StableAbi>::LAYOUT).replace("After", "T");
        assert_ne!(before, after);
    }
}
