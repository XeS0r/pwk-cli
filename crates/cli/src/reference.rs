//! Secret references `pw://<vault>/<folder>/…/<item>/<field>[?attribute=totp]` and the
//! `{{ pw://… }}` placeholders of `inject`.

use std::collections::HashMap;
use std::fmt;
use std::ops::Range;
use std::str::FromStr;

use anyhow::Context as _;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use zeroize::Zeroizing;

/// URL scheme of a reference.
pub const SCHEME: &str = "pw://";

/// Characters percent-encoded when a reference is printed (non-ASCII is always encoded).
const SEGMENT: &AsciiSet = &CONTROLS
    .add(b'%')
    .add(b'/')
    .add(b'?')
    .add(b'#')
    .add(b'{')
    .add(b'}');

/// What to take from the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Attribute {
    /// The current TOTP code instead of the stored secret.
    Totp,
}

/// A parsed secret reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Reference {
    /// Vault name or ID.
    pub vault: String,
    /// Folder path below the vault (names or IDs), possibly empty.
    pub folders: Vec<String>,
    /// Item name or ID.
    pub item: String,
    /// `password`, `login`, `name`, `url`, `description`, `tags` or a custom field name.
    pub field: String,
    /// `?attribute=…`.
    pub attribute: Option<Attribute>,
}

/// An invalid reference.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid reference `{reference}`: {reason}")]
pub struct ReferenceError {
    /// The reference as written.
    pub reference: String,
    /// What is wrong.
    pub reason: String,
}

impl Reference {
    /// Whether `value` is meant as a reference (starts with `pw://`).
    #[must_use]
    pub fn is_reference(value: &str) -> bool {
        value.starts_with(SCHEME)
    }
}

impl FromStr for Reference {
    type Err = ReferenceError;

    fn from_str(text: &str) -> Result<Self, ReferenceError> {
        let fail = |reason: String| ReferenceError {
            reference: text.to_owned(),
            reason,
        };
        let rest = text
            .strip_prefix(SCHEME)
            .ok_or_else(|| fail("must start with pw://".into()))?;
        let (path, query) = match rest.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (rest, None),
        };
        let mut segments = Vec::new();
        for (i, raw) in path.split('/').enumerate() {
            if raw.is_empty() {
                return Err(fail(format!(
                    "path segment {} is empty (write `/` inside a name as %2F)",
                    i + 1
                )));
            }
            let decoded = percent_decode_str(raw).decode_utf8().map_err(|_| {
                fail(format!(
                    "path segment {} is not valid percent-encoded UTF-8",
                    i + 1
                ))
            })?;
            segments.push(decoded.into_owned());
        }
        if segments.len() < 3 {
            return Err(fail(
                "expected at least vault, item and field: pw://vault/[folder/…/]item/field".into(),
            ));
        }
        let attribute = match query {
            None => None,
            Some(query) => parse_query(query).map_err(fail)?,
        };
        let field = segments.pop().unwrap_or_default();
        let item = segments.pop().unwrap_or_default();
        let vault = segments.remove(0);
        Ok(Self {
            vault,
            folders: segments,
            item,
            field,
            attribute,
        })
    }
}

fn parse_query(query: &str) -> Result<Option<Attribute>, String> {
    let mut attribute = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let decode = |s: &str| percent_decode_str(s).decode_utf8_lossy().into_owned();
        let (key, value) = (decode(key), decode(value));
        if key != "attribute" {
            return Err(format!(
                "unknown query parameter `{key}` (only attribute=totp is supported)"
            ));
        }
        attribute = Some(match value.to_ascii_lowercase().as_str() {
            "totp" | "otp" => Attribute::Totp,
            _ => {
                return Err(format!(
                    "unknown attribute `{value}` (only totp is supported)"
                ));
            }
        });
    }
    Ok(attribute)
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(SCHEME)?;
        let segments = std::iter::once(&self.vault)
            .chain(&self.folders)
            .chain([&self.item, &self.field]);
        for (i, segment) in segments.enumerate() {
            if i > 0 {
                f.write_str("/")?;
            }
            write!(f, "{}", utf8_percent_encode(segment, SEGMENT))?;
        }
        if self.attribute == Some(Attribute::Totp) {
            f.write_str("?attribute=totp")?;
        }
        Ok(())
    }
}

/// A `{{ pw://… }}` placeholder found in a template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placeholder {
    /// Byte range of the whole placeholder, braces included.
    pub range: Range<usize>,
    /// The parsed reference.
    pub reference: Reference,
}

/// Every `{{ pw://… }}` in `text`, in order. Whitespace inside the braces is optional;
/// a reference ends at the next `}}`. `{{` not followed by `pw://` is left alone. Extra
/// braces around a placeholder stay: `{{{ pw://… }}}` renders as `{value}`.
pub fn find_placeholders(text: &str) -> anyhow::Result<Vec<Placeholder>> {
    let mut found = Vec::new();
    let mut pos = 0;
    while let Some(offset) = text[pos..].find("{{") {
        let start = pos + offset;
        let inner_start = start + 2;
        let after = &text[inner_start..];
        let trimmed = after.trim_start();
        if !trimmed.starts_with(SCHEME) {
            // One byte on: in `{{{ pw://… }}}` the placeholder starts at the second `{`.
            pos = start + 1;
            continue;
        }
        let line = text[..start].matches('\n').count() + 1;
        let Some(close) = after.find("}}") else {
            anyhow::bail!("line {line}: `{{{{ pw://` without closing `}}}}`");
        };
        let inner = after[..close].trim();
        let reference: Reference = inner.parse().with_context(|| format!("line {line}"))?;
        let end = inner_start + close + 2;
        found.push(Placeholder {
            range: start..end,
            reference,
        });
        pos = end;
    }
    Ok(found)
}

/// Replaces every placeholder in `text` with `resolve(reference)`; each distinct
/// reference is resolved once.
pub fn replace_placeholders(
    text: &str,
    mut resolve: impl FnMut(&Reference) -> anyhow::Result<String>,
) -> anyhow::Result<Zeroizing<String>> {
    let placeholders = find_placeholders(text)?;
    let mut values: HashMap<&Reference, Zeroizing<String>> = HashMap::new();
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    let mut pos = 0;
    for placeholder in &placeholders {
        out.push_str(&text[pos..placeholder.range.start]);
        if !values.contains_key(&placeholder.reference) {
            let value = resolve(&placeholder.reference)
                .with_context(|| format!("cannot resolve {}", placeholder.reference))?;
            values.insert(&placeholder.reference, Zeroizing::new(value));
        }
        out.push_str(&values[&placeholder.reference]);
        pos = placeholder.range.end;
    }
    out.push_str(&text[pos..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> Reference {
        s.parse().unwrap()
    }

    #[test]
    fn parse_minimal() {
        let reference = r("pw://Infra/Prod DB/password");
        assert_eq!(reference.vault, "Infra");
        assert!(reference.folders.is_empty());
        assert_eq!(reference.item, "Prod DB");
        assert_eq!(reference.field, "password");
        assert_eq!(reference.attribute, None);
    }

    #[test]
    fn parse_folders_and_attribute() {
        let reference = r("pw://Infra/eu/db/Prod%20DB/otp?attribute=totp");
        assert_eq!(reference.folders, vec!["eu", "db"]);
        assert_eq!(reference.item, "Prod DB");
        assert_eq!(reference.field, "otp");
        assert_eq!(reference.attribute, Some(Attribute::Totp));
    }

    #[test]
    fn percent_decoding() {
        let reference = r("pw://A%2FB/f%3Fx/%C3%BCber/my%25field");
        assert_eq!(reference.vault, "A/B");
        assert_eq!(reference.item, "über");
        assert_eq!(reference.folders, vec!["f?x"]);
        assert_eq!(reference.field, "my%field");
        // Display re-encodes and round-trips.
        assert_eq!(
            reference.to_string(),
            "pw://A%2FB/f%3Fx/%C3%BCber/my%25field"
        );
        assert_eq!(r(&reference.to_string()), reference);
    }

    #[test]
    fn bad_references() {
        let err = |s: &str| s.parse::<Reference>().unwrap_err().to_string();
        assert!(err("op://a/b/c").contains("must start with pw://"));
        assert!(err("pw://a/b").contains("at least vault, item and field"));
        assert!(err("pw://a//b/c").contains("segment 2 is empty"));
        assert!(err("pw://a/b/c/").contains("segment 4 is empty"));
        assert!(err("pw:///a/b").contains("segment 1 is empty"));
        assert!(err("pw://a/b/%FF").contains("not valid percent-encoded UTF-8"));
        assert!(err("pw://a/b/c?attribute=hotp").contains("unknown attribute"));
        assert!(err("pw://a/b/c?x=1").contains("unknown query parameter `x`"));
    }

    #[test]
    fn find_and_replace() {
        let text = "user={{pw://V/item/login}}\npass={{ pw://V/item/password }} again \
                    {{  pw://V/item/password}}\nkeep {{ not a ref }} and {{x}}\n";
        let found = find_placeholders(text).unwrap();
        assert_eq!(found.len(), 3);
        assert_eq!(&text[found[0].range.clone()], "{{pw://V/item/login}}");
        let mut calls = Vec::new();
        let out = replace_placeholders(text, |reference| {
            calls.push(reference.field.clone());
            Ok(format!("<{}>", reference.field))
        })
        .unwrap();
        assert_eq!(
            out.as_str(),
            "user=<login>\npass=<password> again <password>\nkeep {{ not a ref }} and {{x}}\n"
        );
        assert_eq!(calls, vec!["login", "password"]);
    }

    #[test]
    fn placeholder_after_extra_brace() {
        // `{{{ pw://… }}}`: the inner `{{ … }}` is the placeholder, the outer braces stay.
        let text = "{{{ pw://V/i/f }}} x{{{{pw://V/i/g}} {{ {{ pw://V/i/f }}";
        let out =
            replace_placeholders(text, |reference| Ok(reference.field.to_uppercase())).unwrap();
        assert_eq!(out.as_str(), "{F} x{{G {{ F");
        let found = find_placeholders("{{{ pw://V/i/f }}}").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range, 1..17);
    }

    #[test]
    fn replace_errors() {
        let err = replace_placeholders("a\n{{ pw://V/i }}", |_| Ok(String::new())).unwrap_err();
        assert!(format!("{err:#}").contains("line 2"));
        let err = replace_placeholders("{{ pw://V/i/f", |_| Ok(String::new())).unwrap_err();
        assert!(err.to_string().contains("without closing"));
        let err =
            replace_placeholders("{{ pw://V/i/f }}", |_| anyhow::bail!("not found")).unwrap_err();
        assert_eq!(format!("{err:#}"), "cannot resolve pw://V/i/f: not found");
        // Text without placeholders is returned unchanged.
        let out = replace_placeholders("plain {{ text", |_| unreachable!()).unwrap();
        assert_eq!(out.as_str(), "plain {{ text");
    }

    #[test]
    fn detection() {
        assert!(Reference::is_reference("pw://a/b/c"));
        assert!(!Reference::is_reference(" pw://a/b/c"));
        assert!(!Reference::is_reference("secret"));
    }
}
