//! Secret-redaction helpers shared across plugins (logs, audit, errors).
//!
//! The substitution layers resolve `${cred://…}` / `${env.…}` into real
//! secrets before a backend connects, so a resolved connection URL can
//! carry credentials in its userinfo (`scheme://user:pass@host`). These
//! helpers strip that userinfo before a value is logged, audited, or put
//! into an error message.

/// What a caller-visible result shows in place of a request header value
/// or a URL query value.
pub const REDACTED: &str = "[redacted]";

/// The header names of a request, each value replaced by [`REDACTED`]. A
/// value may hold a resolved secret, credential or environment value, and
/// once resolved nothing tells which, so every value is withheld.
pub fn redact_header_values(
    headers: &std::collections::BTreeMap<String, String>,
) -> std::collections::BTreeMap<String, String> {
    headers
        .keys()
        .map(|name| (name.clone(), REDACTED.to_owned()))
        .collect()
}

/// A request URL as a caller may see it: the userinfo removed and every
/// query value replaced by [`REDACTED`], since either can carry a resolved
/// secret. The scheme, host, path, query names and fragment stay.
pub fn redact_url_for_display(url: &str) -> String {
    let url = redact_url_password(url);
    let (before_fragment, fragment) = match url.split_once('#') {
        Some((before, fragment)) => (before, Some(fragment)),
        None => (url.as_str(), None),
    };
    let Some((base, query)) = before_fragment.split_once('?') else {
        return url;
    };
    let query = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, _)) => format!("{name}={REDACTED}"),
            None => pair.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("&");
    match fragment {
        Some(fragment) => format!("{base}?{query}#{fragment}"),
        None => format!("{base}?{query}"),
    }
}

/// Strip the userinfo (`user:pass@`) from a single URL, preserving the
/// scheme, host, port, path, and query. An `@` outside the authority
/// (in a path or query) is left intact.
pub fn redact_url_password(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_owned();
    };
    let authority_start = scheme_end + 3;
    let authority_end = url[authority_start..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| authority_start + i);
    let authority = &url[authority_start..authority_end];
    match authority.rfind('@') {
        Some(rel_at) => format!(
            "{}{}",
            &url[..authority_start],
            &url[authority_start + rel_at + 1..]
        ),
        None => url.to_owned(),
    }
}

/// Redact credential userinfo from every URL-shaped token in a larger
/// string (a log line or error reason that embeds one or more URLs).
/// Non-URL tokens pass through unchanged.
pub fn redact_in_text(text: &str) -> String {
    text.split_whitespace()
        .map(|tok| {
            let (core, trail) = split_trailing_punct(tok);
            if core.contains("://") {
                let redacted = redact_url_password(core);
                if redacted == core {
                    tok.to_owned()
                } else {
                    format!("{redacted}{trail}")
                }
            } else {
                tok.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Redact credential userinfo from every string leaf of a JSON value
/// in place (objects, arrays, and bare strings). Used to scrub
/// plugin-supplied telemetry — metric label values, span attributes —
/// before they reach a long-retained metrics/tracing sink, since those
/// values are attacker-chosen and may carry a resolved `scheme://user:pass@host`.
/// Non-string leaves and non-URL strings pass through unchanged.
pub fn redact_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => {
            let red = redact_in_text(s);
            if red != *s {
                *s = red;
            }
        }
        serde_json::Value::Array(items) => {
            for it in items.iter_mut() {
                redact_value(it);
            }
        }
        serde_json::Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                redact_value(v);
            }
        }
        _ => {}
    }
}

/// Split trailing punctuation (that commonly follows a URL in prose,
/// e.g. `'…@host)'` or `'…@host.'`) off the end of a token so it doesn't
/// get folded into the authority parse.
fn split_trailing_punct(tok: &str) -> (&str, &str) {
    let end = tok
        .rfind(|c: char| {
            !matches!(
                c,
                ')' | ']' | '}' | '>' | ',' | '.' | ';' | ':' | '"' | '\''
            )
        })
        .map_or(0, |i| i + tok[i..].chars().next().map_or(1, char::len_utf8));
    tok.split_at(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_values_are_withheld_and_names_kept() {
        let headers: std::collections::BTreeMap<String, String> = [
            ("authorization".to_owned(), "Bearer s3cret".to_owned()),
            ("x-static".to_owned(), "plain".to_owned()),
        ]
        .into();
        let shown = redact_header_values(&headers);
        assert_eq!(shown.len(), 2);
        assert!(shown.values().all(|v| v == REDACTED), "{shown:?}");
        assert!(!format!("{shown:?}").contains("s3cret"));
    }

    #[test]
    fn display_url_drops_userinfo_and_query_values() {
        assert_eq!(
            redact_url_for_display("https://u:p@api.test/v1/x?key=s3cret&page=2#top"),
            "https://api.test/v1/x?key=[redacted]&page=[redacted]#top"
        );
        assert_eq!(
            redact_url_for_display("https://api.test/v1/x?flag"),
            "https://api.test/v1/x?flag"
        );
        assert_eq!(
            redact_url_for_display("https://api.test/v1/x"),
            "https://api.test/v1/x"
        );
    }

    #[test]
    fn strips_userinfo_single_url() {
        assert_eq!(
            redact_url_password("nats://user:secret@host:4222"),
            "nats://host:4222"
        );
        assert_eq!(
            redact_url_password("postgres://u:p@db/app?x=1"),
            "postgres://db/app?x=1"
        );
    }

    #[test]
    fn at_in_path_or_query_preserved() {
        assert_eq!(
            redact_url_password("redis://host:6379/0?token=a@b"),
            "redis://host:6379/0?token=a@b"
        );
    }

    #[test]
    fn at_inside_password_stripped() {
        assert_eq!(
            redact_url_password("nats://user:p@ss@host:4222"),
            "nats://host:4222"
        );
    }

    #[test]
    fn no_userinfo_unchanged() {
        assert_eq!(redact_url_password("nats://host:4222"), "nats://host:4222");
        assert_eq!(redact_url_password("not a url"), "not a url");
    }

    #[test]
    fn redact_value_scrubs_string_leaves() {
        let mut v = serde_json::json!({
            "note": "connect nats://user:secret@host:4222 ok",
            "count": 7,
            "nested": ["amqps://u:p@broker/vhost", "plain text"],
        });
        redact_value(&mut v);
        assert_eq!(v["note"], "connect nats://host:4222 ok");
        assert_eq!(v["count"], 7);
        assert_eq!(v["nested"][0], "amqps://broker/vhost");
        assert_eq!(v["nested"][1], "plain text");
    }

    #[test]
    fn redacts_url_embedded_in_text() {
        assert_eq!(
            redact_in_text("failed to connect to nats://user:secret@host:4222 after retry"),
            "failed to connect to nats://host:4222 after retry"
        );
        // Trailing punctuation kept outside the authority parse.
        assert_eq!(
            redact_in_text("(url=amqps://u:p@broker/vhost)"),
            "(url=amqps://broker/vhost)"
        );
    }
}
