//! Bytes in a JSON payload that crosses the plugin boundary.

use base64::Engine as _;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Bytes in a JSON payload that crosses the plugin boundary: an array of
/// numbers, one per byte, which every release reads and writes, or a base64
/// string, which the two sides use once the plugin has declared that it reads
/// one. Either form reads; `base64` picks the form written.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WireBytes {
    pub bytes: Vec<u8>,
    pub base64: bool,
}

impl WireBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>, base64: bool) -> Self {
        Self { bytes, base64 }
    }
}

impl Serialize for WireBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.base64 {
            serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(&self.bytes))
        } else {
            self.bytes.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for WireBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(WireBytesVisitor)
    }
}

struct WireBytesVisitor;

impl<'de> Visitor<'de> for WireBytesVisitor {
    type Value = WireBytes;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a base64 string or an array of bytes")
    }

    fn visit_str<E: de::Error>(self, encoded: &str) -> Result<WireBytes, E> {
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map(|bytes| WireBytes::new(bytes, true))
            .map_err(E::custom)
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<WireBytes, E> {
        Ok(WireBytes::new(bytes.to_vec(), false))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<WireBytes, A::Error> {
        let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(1 << 16));
        while let Some(byte) = seq.next_element::<u8>()? {
            bytes.push(byte);
        }
        Ok(WireBytes::new(bytes, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_form_writes_as_asked_and_both_read() {
        let bytes = b"\x00mcpg\xff".to_vec();
        let array = serde_json::to_string(&WireBytes::new(bytes.clone(), false)).unwrap();
        assert_eq!(array, "[0,109,99,112,103,255]");
        let base64 = serde_json::to_string(&WireBytes::new(bytes.clone(), true)).unwrap();
        assert_eq!(base64, "\"AG1jcGf/\"");

        assert_eq!(
            serde_json::from_str::<WireBytes>(&array).unwrap(),
            WireBytes::new(bytes.clone(), false)
        );
        assert_eq!(
            serde_json::from_str::<WireBytes>(&base64).unwrap(),
            WireBytes::new(bytes, true)
        );
        assert_eq!(
            serde_json::from_str::<WireBytes>("[]").unwrap(),
            WireBytes::new(Vec::new(), false)
        );
        assert_eq!(
            serde_json::from_str::<WireBytes>("\"\"").unwrap(),
            WireBytes::new(Vec::new(), true)
        );
    }

    #[test]
    fn what_is_neither_form_does_not_read() {
        assert!(serde_json::from_str::<WireBytes>("\"not base64!\"").is_err());
        assert!(serde_json::from_str::<WireBytes>("[256]").is_err());
        assert!(serde_json::from_str::<WireBytes>("{}").is_err());
    }
}
