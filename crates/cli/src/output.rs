//! Output formats: aligned tables, JSON, masked values and the error printer.

use std::io::{self, IsTerminal as _, Write as _};

/// Placeholder shown instead of a hidden secret.
pub const MASK: &str = "********";

/// Output format of listings and objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// Aligned columns for people.
    Table,
    /// Pretty-printed JSON for scripts.
    Json,
}

impl Format {
    /// `explicit` if given, else `table` when stdout is a terminal and `json` otherwise.
    #[must_use]
    pub fn resolve(explicit: Option<Self>) -> Self {
        explicit.unwrap_or_else(|| {
            if io::stdout().is_terminal() {
                Self::Table
            } else {
                Self::Json
            }
        })
    }
}

/// `value`, or [`MASK`] unless `reveal`.
#[must_use]
pub fn masked(value: &str, reveal: bool) -> &str {
    if reveal { value } else { MASK }
}

/// A table with a header row; cells are left-aligned and separated by two spaces.
#[derive(Debug, Clone, Default)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// An empty table with these column headers.
    pub fn new<I, S>(headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            headers: headers.into_iter().map(Into::into).collect(),
            rows: Vec::new(),
        }
    }

    /// Appends a row; missing cells are empty, extra cells are dropped.
    pub fn push<I, S>(&mut self, row: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut row: Vec<String> = row.into_iter().map(Into::into).collect();
        row.resize(self.headers.len(), String::new());
        self.rows.push(row);
    }

    /// Number of data rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// True without data rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The rendered table, one line per row, each ending in `\n`. Trailing spaces are
    /// trimmed; control characters in cells are shown as spaces.
    #[must_use]
    pub fn render(&self) -> String {
        let clean = |s: &str| -> String {
            s.chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect()
        };
        let lines: Vec<Vec<String>> = std::iter::once(&self.headers)
            .chain(&self.rows)
            .map(|row| row.iter().map(|cell| clean(cell)).collect())
            .collect();
        let mut widths = vec![0; self.headers.len()];
        for row in &lines {
            for (width, cell) in widths.iter_mut().zip(row) {
                *width = (*width).max(cell.chars().count());
            }
        }
        let mut out = String::new();
        for row in &lines {
            let mut line = String::new();
            for (i, (cell, width)) in row.iter().zip(&widths).enumerate() {
                if i > 0 {
                    line.push_str("  ");
                }
                line.push_str(cell);
                let pad = width - cell.chars().count();
                line.extend(std::iter::repeat_n(' ', pad));
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }

    /// Writes the rendered table to stdout.
    pub fn print(&self) -> io::Result<()> {
        write_stdout(&self.render())
    }
}

/// `key  value` lines with aligned values (the table view of a single object).
#[must_use]
pub fn render_pairs<K: AsRef<str>, V: AsRef<str>>(pairs: &[(K, V)]) -> String {
    let mut table = Table::new(["", ""]);
    for (key, value) in pairs {
        table.push([key.as_ref(), value.as_ref()]);
    }
    // Drop the (empty) header line.
    table
        .render()
        .split_once('\n')
        .map(|(_, rest)| rest.to_owned())
        .unwrap_or_default()
}

/// A Unix timestamp as `YYYY-MM-DD HH:MM:SS UTC`.
#[must_use]
pub fn format_timestamp(unix: u64) -> String {
    let days = unix / 86_400;
    let secs = unix % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// `value` as pretty-printed JSON with a trailing newline.
pub fn to_json<T: serde::Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    Ok(text)
}

/// Prints `value` as pretty JSON to stdout.
pub fn print_json<T: serde::Serialize + ?Sized>(value: &T) -> anyhow::Result<()> {
    write_stdout(&to_json(value)?)?;
    Ok(())
}

/// Writes `text` to stdout and flushes; a closed pipe is not an error.
pub fn write_stdout(text: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

/// `pwk: <message>: <cause>: …` for an error and its chain.
#[must_use]
pub fn format_error(error: &anyhow::Error) -> String {
    format!("pwk: {error:#}")
}

/// Prints [`format_error`] to stderr.
pub fn print_error(error: &anyhow::Error) {
    let _ = writeln!(io::stderr().lock(), "{}", format_error(error));
}

/// Prints an informational message to stderr unless `quiet`.
pub fn info(quiet: bool, message: &str) {
    if !quiet {
        let _ = writeln!(io::stderr().lock(), "{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_aligns_columns() {
        let mut table = Table::new(["ID", "NAME", "X"]);
        table.push(["1", "alpha", ""]);
        table.push(["22222", "b"]);
        table.push(["3", "ü\tx", "z"]);
        assert_eq!(
            table.render(),
            "ID     NAME   X\n1      alpha\n22222  b\n3      ü x    z\n"
        );
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn empty_table_has_header() {
        let table = Table::new(["A", "B"]);
        assert!(table.is_empty());
        assert_eq!(table.render(), "A  B\n");
    }

    #[test]
    fn pairs() {
        assert_eq!(
            render_pairs(&[("name", "x"), ("password", MASK)]),
            "name      x\npassword  ********\n"
        );
    }

    #[test]
    fn masking() {
        assert_eq!(masked("s3cret", false), MASK);
        assert_eq!(masked("s3cret", true), "s3cret");
    }

    #[test]
    fn json_is_pretty_with_newline() {
        let text = to_json(&serde_json::json!({"a": 1})).unwrap();
        assert_eq!(text, "{\n  \"a\": 1\n}\n");
    }

    #[test]
    fn timestamps() {
        assert_eq!(format_timestamp(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_timestamp(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(format_timestamp(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(format_timestamp(4_102_444_799), "2099-12-31 23:59:59 UTC");
    }

    #[test]
    fn error_chain() {
        let error = anyhow::anyhow!("root").context("outer");
        assert_eq!(format_error(&error), "pwk: outer: root");
    }
}
