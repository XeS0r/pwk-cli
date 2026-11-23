//! A small dotenv parser for `run --env-file`.
//!
//! Syntax: `KEY=value` per line, blank lines and `#` comments, optional `export `
//! prefix. Values are unquoted (trimmed; ` #` starts a comment), single-quoted (literal)
//! or double-quoted (escapes `\n`, `\r`, `\t`, `\\`, `\"`). Quoted values end on the same
//! line.

/// A syntax error with its line number (1-based).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {message}")]
pub struct DotenvError {
    /// Line number, starting at 1.
    pub line: usize,
    /// What is wrong.
    pub message: String,
}

/// Parses dotenv text into `(key, value)` pairs in file order (later duplicates win
/// when collected into a map).
pub fn parse(text: &str) -> Result<Vec<(String, String)>, DotenvError> {
    let mut pairs = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let fail = |message: String| DotenvError {
            line: index + 1,
            message,
        };
        let line = raw.trim_start_matches('\u{feff}').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = match line.strip_prefix("export") {
            Some(rest) if rest.starts_with([' ', '\t']) => rest.trim_start(),
            _ => line,
        };
        let Some((key, value)) = line.split_once('=') else {
            return Err(fail("expected KEY=value".into()));
        };
        let key = key.trim_end();
        if !is_valid_key(key) {
            return Err(fail(format!(
                "invalid variable name `{key}` (use letters, digits and `_`, not starting with a digit)"
            )));
        }
        let value = parse_value(value.trim_start()).map_err(fail)?;
        pairs.push((key.to_owned(), value));
    }
    Ok(pairs)
}

fn is_valid_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn parse_value(value: &str) -> Result<String, String> {
    let (parsed, rest) = if let Some(inner) = value.strip_prefix('\'') {
        let end = inner
            .find('\'')
            .ok_or_else(|| "unterminated single quote".to_owned())?;
        (inner[..end].to_owned(), &inner[end + 1..])
    } else if let Some(inner) = value.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = inner.char_indices();
        let mut end = None;
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => {
                    end = Some(i);
                    break;
                }
                '\\' => match chars.next() {
                    Some((_, 'n')) => out.push('\n'),
                    Some((_, 'r')) => out.push('\r'),
                    Some((_, 't')) => out.push('\t'),
                    Some((_, '\\')) => out.push('\\'),
                    Some((_, '"')) => out.push('"'),
                    Some((_, other)) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => break,
                },
                c => out.push(c),
            }
        }
        let end = end.ok_or_else(|| "unterminated double quote".to_owned())?;
        (out, &inner[end + 1..])
    } else {
        // Unquoted: a `#` after whitespace starts a comment.
        let mut end = value.len();
        let bytes = value.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
                end = i;
                break;
            }
        }
        return Ok(value[..end].trim_end().to_owned());
    };
    let rest = rest.trim_start();
    if !rest.is_empty() && !rest.starts_with('#') {
        return Err(format!("unexpected text after the closing quote: `{rest}`"));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(text: &str) -> Vec<(String, String)> {
        parse(text).unwrap()
    }

    fn one(text: &str) -> String {
        let mut p = pairs(text);
        assert_eq!(p.len(), 1, "{text}");
        p.remove(0).1
    }

    #[test]
    fn basics() {
        let text = "# comment\n\nA=1\nexport B = two words \n  C=pw://V/i/password\r\nD=\n";
        assert_eq!(
            pairs(text),
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "two words".into()),
                ("C".into(), "pw://V/i/password".into()),
                ("D".into(), String::new()),
            ]
        );
    }

    #[test]
    fn comments_in_values() {
        assert_eq!(one("A=x # note"), "x");
        assert_eq!(one("A=x#y"), "x#y");
        assert_eq!(one("A=#y"), "");
        assert_eq!(one("A='x # y' # note"), "x # y");
    }

    #[test]
    fn quotes() {
        assert_eq!(one(r"A='a\nb $X'"), r"a\nb $X");
        assert_eq!(one(r#"A="a\nb\t\"q\" \\ \x""#), "a\nb\t\"q\" \\ \\x");
        assert_eq!(one(r#"A="""#), "");
        assert_eq!(one("A=\"it's\""), "it's");
        assert_eq!(one("exportX=1"), "1");
        assert_eq!(pairs("exportX=1")[0].0, "exportX");
    }

    #[test]
    fn errors_have_line_numbers() {
        let err = parse("A=1\n\nnot a pair\n").unwrap_err();
        assert_eq!(err.line, 3);
        assert_eq!(err.to_string(), "line 3: expected KEY=value");
        assert_eq!(parse("1A=x").unwrap_err().line, 1);
        assert!(parse("A B=x").is_err());
        assert!(parse("=x").is_err());
        assert!(
            parse("A='open")
                .unwrap_err()
                .message
                .contains("unterminated single")
        );
        assert!(
            parse("A=\"open\\\"")
                .unwrap_err()
                .message
                .contains("unterminated double")
        );
        assert!(
            parse("A='x' y")
                .unwrap_err()
                .message
                .contains("after the closing quote")
        );
    }
}
